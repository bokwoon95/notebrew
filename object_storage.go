package notebrew

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path"
	"path/filepath"

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

	// Deletes an object from a bucket. It returns no error if the object does
	// not exist.
	Delete(ctx context.Context, key string) error

	// Copies an object identified by srcKey into destKey. srcKey should exist.
	// If destKey already exists, it should be replaced.
	Copy(ctx context.Context, srcKey, destKey string) error
}

// S3ObjectStorage implements ObjectStorage via an S3-compatible provider.
type S3ObjectStorage struct {
	// S3 SDK client.
	Client *s3.Client

	// S3 Bucket to put objects in.
	Bucket string

	// File extension to Content-Type map.
	ContentTypeMap map[string]string

	// Logger is used for reporting errors that cannot be handled and are
	// thrown away.
	Logger *slog.Logger

	// values is a key-value store containing values used by some S3 Object
	// operations. Currently, the following values are recognized:
	//
	// - "httprange" => string (value of the HTTP Range header passed to GetObject)
	values map[string]any
}

var _ ObjectStorage = (*S3ObjectStorage)(nil)

// S3StorageConfig holds the parameters needed to construct an S3ObjectStorage.
type S3StorageConfig struct {
	// (Required) S3 endpoint.
	Endpoint string

	// (Required) S3 region.
	Region string

	// (Required) S3 bucket.
	Bucket string

	// (Required) S3 access key ID.
	AccessKeyID string

	// (Required) S3 secret access key.
	SecretAccessKey string

	// File extension to Content-Type map.
	ContentTypeMap map[string]string

	// (Required) Logger is used for reporting errors that cannot be handled
	// and are thrown away.
	Logger *slog.Logger
}

// NewS3Storage constructs a new S3ObjectStorage.
func NewS3Storage(ctx context.Context, config S3StorageConfig) (*S3ObjectStorage, error) {
	storage := &S3ObjectStorage{
		Client: s3.New(s3.Options{
			BaseEndpoint: aws.String(config.Endpoint),
			Region:       config.Region,
			Credentials:  aws.NewCredentialsCache(credentials.NewStaticCredentialsProvider(config.AccessKeyID, config.SecretAccessKey, "")),
		}),
		Bucket:         config.Bucket,
		ContentTypeMap: config.ContentTypeMap,
		Logger:         config.Logger,
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

func (storage *S3ObjectStorage) WithValues(values map[string]any) ObjectStorage {
	return &S3ObjectStorage{
		Client:         storage.Client,
		Bucket:         storage.Bucket,
		ContentTypeMap: storage.ContentTypeMap,
		Logger:         storage.Logger,
		values:         values,
	}
}

// Get implements the Get ObjectStorage operation for S3ObjectStorage.
func (storage *S3ObjectStorage) Get(ctx context.Context, key string) (io.ReadCloser, error) {
	var httpRange *string
	if value, ok := storage.values["httprange"].(string); ok && value != "" {
		httpRange = &value
	}
	output, err := storage.Client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: &storage.Bucket,
		Key:    aws.String(key),
		Range:  httpRange,
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
	if output.ContentRange != nil {
		storage.values["httpcontentrange"] = *output.ContentRange
	}
	return output.Body, nil
}

// Put implements the Put ObjectStorage operation for S3ObjectStorage.
func (storage *S3ObjectStorage) Put(ctx context.Context, key string, reader io.Reader) error {
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
	contentType := storage.ContentTypeMap[path.Ext(key)]
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	createResult, err := storage.Client.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{
		Bucket:       &storage.Bucket,
		Key:          aws.String(key),
		CacheControl: aws.String("max-age=31536000, immutable" /* 1 year */),
		ContentType:  aws.String(contentType),
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

// Delete implements the Delete ObjectStorage operation for S3ObjectStorage.
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

// Copy implements the Copy ObjectStorage operation for S3ObjectStorage.
func (storage *S3ObjectStorage) Copy(ctx context.Context, srcKey, destKey string) error {
	_, err := storage.Client.CopyObject(ctx, &s3.CopyObjectInput{
		Bucket:     &storage.Bucket,
		CopySource: aws.String(storage.Bucket + "/" + srcKey),
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
}

// NewDirObjectStorage constructs a new DirectoryObjectStorage.
func NewDirObjectStorage(rootDir, tempDir string) (*DirectoryObjectStorage, error) {
	var err error
	rootDir, err = filepath.Abs(filepath.FromSlash(rootDir))
	if err != nil {
		return nil, err
	}
	directoryObjectStorage := &DirectoryObjectStorage{
		RootDir: filepath.FromSlash(rootDir),
	}
	return directoryObjectStorage, nil
}

// Get implements the Get ObjectStorage operation for DirectoryObjectStorage.
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

// Put implements the Put ObjectStorage operation for DirectoryObjectStorage.
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

// Delete implements the Delete ObjectStorage operation for
// DirectoryObjectStorage.
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

// Copy implements the Copy ObjectStorage operation for DirectoryObjectStorage.
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
