package notebrew

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	"github.com/bokwoon95/notebrew/stacktrace"
)

// ObjectStorage represents an object storage provider.
type ObjectStorage interface {
	// Gets an object from a bucket.
	Get(ctx context.Context, key string) (io.ReadCloser, error)

	// Puts an object into a bucket. If key already exists, it should be
	// replaced.
	Put(ctx context.Context, key string, reader io.Reader) error

	// Deletes an object from a bucket, regardless of whether it exists.
	Delete(ctx context.Context, key string) error

	// Copies an object identified by srcKey into destKey. srcKey should exist.
	// If destKey already exists, it should be replaced.
	Copy(ctx context.Context, srcKey, destKey string) error
}

// S3ObjectStorage implements ObjectStorage via an S3-compatible provider.
type S3ObjectStorage struct {
	Client *s3.Client   // S3 SDK client.
	Bucket string       // S3 Bucket to put objects in.
	Logger *slog.Logger // slog logger, must not be null.
}

var _ ObjectStorage = (*S3ObjectStorage)(nil)

// S3StorageConfig holds the parameters needed to construct an S3ObjectStorage.
type S3StorageConfig struct {
	Endpoint        string       // S3 endpoint.
	Region          string       // S3 region.
	Bucket          string       // S3 bucket.
	AccessKeyID     string       // S3 access key ID.
	SecretAccessKey string       // S3 secret access key.
	Logger          *slog.Logger // slog logger, must not be null.
}

// NewS3Storage constructs a new S3ObjectStorage.
func NewS3Storage(ctx context.Context, config S3StorageConfig) (*S3ObjectStorage, error) {
	storage := &S3ObjectStorage{
		Client: s3.New(s3.Options{
			BaseEndpoint: aws.String(config.Endpoint),
			Region:       config.Region,
			Credentials:  aws.NewCredentialsCache(credentials.NewStaticCredentialsProvider(config.AccessKeyID, config.SecretAccessKey, "")),
		}),
		Bucket: config.Bucket,
		Logger: config.Logger,
	}
	// Ping the bucket and see if we have access.
	_, err := storage.Client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
		Bucket:  &storage.Bucket,
		MaxKeys: aws.Int32(1),
	})
	if err != nil {
		return nil, err
	}
	return storage, nil
}

// Gets an object from a bucket.
func (storage *S3ObjectStorage) Get(ctx context.Context, key string) (io.ReadCloser, error) {
	output, err := storage.Client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: &storage.Bucket,
		Key:    aws.String(key),
	})
	if err != nil {
		var apiErr smithy.APIError
		if errors.As(err, &apiErr) {
			if apiErr.ErrorCode() == "NoSuchKey" {
				return nil, &fs.PathError{Op: "get", Path: key, Err: fs.ErrNotExist}
			}
		}
		return nil, stacktrace.New(err)
	}
	return output.Body, nil
}

// Puts an object into a bucket. If key already exists, it should be replaced.
func (storage *S3ObjectStorage) Put(ctx context.Context, key string, reader io.Reader) error {
	fileType, ok := AllowedFileTypes[path.Ext(key)]
	if !ok || !fileType.Has(AttributeObject) {
		return fmt.Errorf("%s: invalid filetype %s", key, path.Ext(key))
	}
	cleanup := func(uploadId *string) {
		_, err := storage.Client.AbortMultipartUpload(context.Background(), &s3.AbortMultipartUploadInput{
			Bucket:   &storage.Bucket,
			Key:      aws.String(key),
			UploadId: uploadId,
		})
		if err != nil {
			storage.Logger.Error(stacktrace.New(err).Error())
		}
	}
	createResult, err := storage.Client.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{
		Bucket:       &storage.Bucket,
		Key:          aws.String(key),
		CacheControl: aws.String("max-age=31536000, immutable" /* 1 year */),
		ContentType:  aws.String(fileType.ContentType),
	})
	if err != nil {
		return stacktrace.New(err)
	}
	var parts []types.CompletedPart
	var partNumber int32
	var buf [5 << 20]byte
	done := false
	for !done {
		n, err := io.ReadFull(reader, buf[:])
		if err != nil {
			if err == io.EOF {
				break
			}
			if err != io.ErrUnexpectedEOF {
				cleanup(createResult.UploadId)
				return stacktrace.New(err)
			}
			done = true
		}
		partNumber++
		uploadResult, err := storage.Client.UploadPart(ctx, &s3.UploadPartInput{
			Bucket:     &storage.Bucket,
			Key:        aws.String(key),
			UploadId:   createResult.UploadId,
			PartNumber: aws.Int32(partNumber),
			Body:       bytes.NewReader(buf[:n]),
		})
		if err != nil {
			cleanup(createResult.UploadId)
			return stacktrace.New(err)
		}
		parts = append(parts, types.CompletedPart{
			ETag:       uploadResult.ETag,
			PartNumber: aws.Int32(partNumber),
		})
	}
	_, err = storage.Client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
		Bucket:   &storage.Bucket,
		Key:      aws.String(key),
		UploadId: createResult.UploadId,
		MultipartUpload: &types.CompletedMultipartUpload{
			Parts: parts,
		},
	})
	if err != nil {
		return stacktrace.New(err)
	}
	return nil
}

// Deletes an object from a bucket, regardless of whether it exists.
func (storage *S3ObjectStorage) Delete(ctx context.Context, key string) error {
	_, err := storage.Client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: &storage.Bucket,
		Key:    aws.String(key),
	})
	if err != nil {
		return stacktrace.New(err)
	}
	return nil
}

// Copies an object identified by srcKey into destKey. srcKey should exist. If
// destKey already exists, it should be replaced.
func (storage *S3ObjectStorage) Copy(ctx context.Context, srcKey, destKey string) error {
	_, err := storage.Client.CopyObject(ctx, &s3.CopyObjectInput{
		Bucket:     &storage.Bucket,
		CopySource: aws.String(srcKey),
		Key:        aws.String(destKey),
	})
	if err != nil {
		var apiErr smithy.APIError
		if errors.As(err, &apiErr) {
			if apiErr.ErrorCode() == "NoSuchKey" {
				return &fs.PathError{Op: "copy", Path: srcKey, Err: fs.ErrNotExist}
			}
		}
		return stacktrace.New(err)
	}
	return nil
}

// DirectoryObjectStorage implements ObjectStorage using a local directory.
type DirectoryObjectStorage struct {
	// Root directory to store objects in.
	RootDir string
	// Temp directory to store objects while they are being written.
	TempDir string
}

// NewDirObjectStorage constructs a new DirectoryObjectStorage.
func NewDirObjectStorage(rootDir, tempDir string) (*DirectoryObjectStorage, error) {
	var err error
	rootDir, err = filepath.Abs(filepath.FromSlash(rootDir))
	if err != nil {
		return nil, err
	}
	tempDir, err = filepath.Abs(filepath.FromSlash(tempDir))
	if err != nil {
		return nil, err
	}
	directoryObjectStorage := &DirectoryObjectStorage{
		RootDir: filepath.FromSlash(rootDir),
		TempDir: filepath.FromSlash(tempDir),
	}
	return directoryObjectStorage, nil
}

// Gets an object from a bucket.
func (storage *DirectoryObjectStorage) Get(ctx context.Context, key string) (io.ReadCloser, error) {
	err := ctx.Err()
	if err != nil {
		return nil, err
	}
	if len(key) < 4 {
		return nil, &fs.PathError{Op: "get", Path: key, Err: fs.ErrInvalid}
	}
	file, err := os.Open(filepath.Join(storage.RootDir, key[:4], key))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, &fs.PathError{Op: "get", Path: key, Err: fs.ErrNotExist}
		}
		return nil, stacktrace.New(err)
	}
	return file, nil
}

func (storage *DirectoryObjectStorage) Put(ctx context.Context, key string, reader io.Reader) error {
	err := ctx.Err()
	if err != nil {
		return err
	}
	if len(key) < 4 {
		return &fs.PathError{Op: "put", Path: key, Err: fs.ErrInvalid}
	}
	file, err := os.OpenFile(filepath.Join(storage.RootDir, key[:4], key), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return stacktrace.New(err)
		}
		err = os.Mkdir(filepath.Join(storage.RootDir, key[:4]), 0755)
		if err != nil && !errors.Is(err, fs.ErrExist) {
			return stacktrace.New(err)
		}
		file, err = os.OpenFile(filepath.Join(storage.RootDir, key[:4], key), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
		if err != nil {
			return stacktrace.New(err)
		}
	}
	_, err = io.Copy(file, reader)
	if err != nil {
		return stacktrace.New(err)
	}
	return nil
}

func (storage *DirectoryObjectStorage) Delete(ctx context.Context, key string) error {
	err := ctx.Err()
	if err != nil {
		return err
	}
	if len(key) < 4 {
		return &fs.PathError{Op: "delete", Path: key, Err: fs.ErrInvalid}
	}
	err = os.Remove(filepath.Join(storage.RootDir, key[:4], key))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return err
		}
		return stacktrace.New(err)
	}
	return nil
}

func (storage *DirectoryObjectStorage) Copy(ctx context.Context, srcKey, destKey string) error {
	err := ctx.Err()
	if err != nil {
		return err
	}
	if len(srcKey) < 4 {
		return &fs.PathError{Op: "copy", Path: srcKey, Err: fs.ErrInvalid}
	}
	if len(destKey) < 4 {
		return &fs.PathError{Op: "copy", Path: destKey, Err: fs.ErrInvalid}
	}
	srcFile, err := os.Open(filepath.Join(storage.RootDir, srcKey[:4], srcKey))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return &fs.PathError{Op: "copy", Path: srcKey, Err: fs.ErrNotExist}
		}
		return stacktrace.New(err)
	}
	defer srcFile.Close()
	destFile, err := os.OpenFile(filepath.Join(storage.RootDir, destKey[:4], destKey), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return stacktrace.New(err)
	}
	defer destFile.Close()
	_, err = io.Copy(destFile, srcFile)
	if err != nil {
		return stacktrace.New(err)
	}
	err = destFile.Close()
	if err != nil {
		return stacktrace.New(err)
	}
	return nil
}

type InMemoryObjectStorage struct {
	mu      sync.RWMutex
	entries map[string][]byte
}

var _ ObjectStorage = (*InMemoryObjectStorage)(nil)

func NewInMemoryObjectStorage() *InMemoryObjectStorage {
	return &InMemoryObjectStorage{
		mu:      sync.RWMutex{},
		entries: make(map[string][]byte),
	}
}

func (storage *InMemoryObjectStorage) Get(ctx context.Context, key string) (io.ReadCloser, error) {
	storage.mu.RLock()
	value, ok := storage.entries[key]
	storage.mu.RUnlock()
	if !ok {
		return nil, &fs.PathError{Op: "get", Path: key, Err: fs.ErrNotExist}
	}
	return io.NopCloser(bytes.NewReader(value)), nil
}

func (storage *InMemoryObjectStorage) Put(ctx context.Context, key string, reader io.Reader) error {
	value, err := io.ReadAll(reader)
	if err != nil {
		return err
	}
	storage.mu.Lock()
	storage.entries[key] = value
	storage.mu.Unlock()
	return nil
}

func (storage *InMemoryObjectStorage) Delete(ctx context.Context, key string) error {
	storage.mu.Lock()
	delete(storage.entries, key)
	storage.mu.Unlock()
	return nil
}

func (storage *InMemoryObjectStorage) Copy(ctx context.Context, srcKey, destKey string) error {
	storage.mu.Lock()
	value, ok := storage.entries[srcKey]
	if !ok {
		return &fs.PathError{Op: "copy", Path: srcKey, Err: fs.ErrNotExist}
	}
	storage.entries[destKey] = value
	storage.mu.Unlock()
	return nil
}
