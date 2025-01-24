package notebrew

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"embed"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"html/template"
	"io"
	"io/fs"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/bokwoon95/notebrew/sq"
	"github.com/bokwoon95/notebrew/stacktrace"
	"github.com/caddyserver/certmagic"
	"github.com/libdns/libdns"
	"github.com/oschwald/maxminddb-golang"
	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/parser"
	"github.com/yuin/goldmark/text"
	"go.uber.org/zap"
	"golang.org/x/crypto/blake2b"
)

// Notebrew represents a notebrew instance.
type Notebrew struct {
	// FS is the file system associated with the notebrew instance.
	FS FS

	// DB is the DB associated with the notebrew instance.
	DB *sql.DB

	// Dialect is Dialect of the database. Only sqlite, postgres and mysql
	// databases are supported.
	Dialect string

	// ErrorCode translates a database error into an dialect-specific error
	// code. If the error is not a database error or if no underlying
	// implementation is provided, ErrorCode should return an empty string.
	ErrorCode func(error) string

	// CMSDomain is the domain that the notebrew is using to serve the CMS.
	// Examples: localhost:6444, notebrew.com
	CMSDomain string

	// CMSDomainHTTPS indicates whether the CMS domain is currently being
	// served over HTTPS.
	CMSDomainHTTPS bool

	// ContentDomain is the domain that the notebrew instance is using to serve
	// the static generated content. Examples: localhost:6444, nbrew.net.
	ContentDomain string

	// ContentDomainHTTPS indicates whether the content domain is currently
	// being served over HTTPS.
	ContentDomainHTTPS bool

	// CDNDomain is the domain of the CDN that notebrew is using to host its
	// images. Examples: cdn.nbrew.net, nbrewcdn.net.
	CDNDomain string

	// LossyImgCmd is the command (must reside in $PATH) used to preprocess
	// images in a lossy way for the web before they are saved to the FS.
	// Images in the notes folder are never preprocessed and are uploaded
	// as-is. This serves as an a escape hatch for users who wish to upload
	// their images without any lossy image preprocessing, as they can upload
	// images to the notes folder first before moving it elsewhere.
	//
	// LossyImgCmd should take in arguments in the form of `<LossyImgCmd>
	// $INPUT_PATH $OUTPUT_PATH`, where $INPUT_PATH is the input path to the
	// raw image and $OUTPUT_PATH is output path where LossyImgCmd should save
	// the preprocessed image.
	LossyImgCmd string

	// VideoCmd is the command (must reside in $PATH) used to preprocess videos
	// in a lossless way for the web before they are saved to the FS.
	//
	// VideoCmd should take in arguments in the form of `<VideoCmd> $INPUT_PATH
	// $OUTPUT_PATH`, where $INPUT_PATH is the input path to the raw video and
	// $OUTPUT_PATH is output path where VideoCmd should save the preprocessed
	// video.
	VideoCmd string

	// (Required) Port is port that notebrew is listening on.
	Port int

	// IP4 is the IPv4 address of the current machine, if notebrew is currently
	// serving either port 80 (HTTP) or 443 (HTTPS).
	IP4 netip.Addr

	// IP6 is the IPv6 address of the current machine, if notebrew is currently
	// serving either port 80 (HTTP) or 443 (HTTPS).
	IP6 netip.Addr

	// Domains is the list of domains that need to point at notebrew for it to
	// work. Does not include user-created domains.
	Domains []string

	// ManagingDomains is the list of domains that the current instance of
	// notebrew is managing SSL certificates for.
	ManagingDomains []string

	// Captcha configuration.
	CaptchaConfig struct {
		// Captcha widget's script src. e.g. https://js.hcaptcha.com/1/api.js,
		// https://challenges.cloudflare.com/turnstile/v0/api.js
		WidgetScriptSrc template.URL

		// Captcha widget's container div class. e.g. h-captcha, cf-turnstile
		WidgetClass string

		// Captcha verification URL to make POST requests to. e.g.
		// https://api.hcaptcha.com/siteverify,
		// https://challenges.cloudflare.com/turnstile/v0/siteverify
		VerificationURL string

		// Captcha response token name. e.g. h-captcha-response,
		// cf-turnstile-response
		ResponseTokenName string

		// Captcha site key.
		SiteKey string

		// Captcha secret key.
		SecretKey string

		// CSP contains the Content-Security-Policy directive names and values
		// required for the captcha widget to work.
		CSP map[string]string
	}

	// Mailer is used to send out transactional emails e.g. password reset
	// emails.
	Mailer *Mailer

	// The default value for the SMTP MAIL FROM instruction.
	MailFrom string

	// The default value for the SMTP Reply-To header.
	ReplyTo string

	// Proxy configuration.
	ProxyConfig struct {
		// RealIPHeaders contains trusted IP addresses to HTTP headers that
		// they are known to populate the real client IP with. e.g. X-Real-IP,
		// True-Client-IP.
		RealIPHeaders map[netip.Addr]string

		// Contains the set of trusted proxy IP addresses. This is used when
		// resolving the real client IP from the X-Forwarded-For HTTP header
		// chain from right (most trusted) to left (most accurate).
		ProxyIPs map[netip.Addr]struct{}
	}

	// DNS provider (required for using wildcard certificates with
	// LetsEncrypt).
	DNSProvider interface {
		libdns.RecordAppender
		libdns.RecordDeleter
		libdns.RecordGetter
		libdns.RecordSetter
	}

	// CertStorage is the magic (certmagic) that automatically provisions SSL
	// certificates for notebrew.
	CertStorage certmagic.Storage

	// CertLogger is the logger used for a certmagic.Config.
	CertLogger *zap.Logger

	// ContentSecurityPolicy is the Content-Security-Policy HTTP header set for
	// every HTML response served on the CMS domain.
	ContentSecurityPolicy string

	// Logger is used for reporting errors that cannot be handled and are
	// thrown away.
	Logger *slog.Logger

	// MaxMindDBReader is the maxmind database reader used to reolve IP
	// addresses to their countries using a maxmind GeoIP database.
	MaxMindDBReader *maxminddb.Reader

	// Error Logging configuration.
	ErrorlogConfig struct {
		// Email address to notify for errors.
		Email string
	}

	// BaseCtx is the base context of the notebrew instance.
	BaseCtx context.Context

	// baseCtxCancel cancels the base context.
	baseCtxCancel func()

	// BaseCtxWaitGroup tracks the number of background jobs spawned by the
	// notebrew instance. Each background job should take in the base context,
	// and should should initiate shutdown when the base context is canceled.
	BaseCtxWaitGroup sync.WaitGroup
}

// New returns a new instance of Notebrew. Each field within it still needs to
// be manually configured.
func New() *Notebrew {
	populateExts()
	baseCtx, baseCtxCancel := context.WithCancel(context.Background())
	nbrew := &Notebrew{
		BaseCtx:       baseCtx,
		baseCtxCancel: baseCtxCancel,
	}
	return nbrew
}

// Close shuts down the notebrew instance as well as any background jobs it may
// have spawned.
func (nbrew *Notebrew) Close() error {
	nbrew.baseCtxCancel()
	defer nbrew.BaseCtxWaitGroup.Wait()
	if nbrew.DB != nil {
		if nbrew.Dialect == "sqlite" {
			nbrew.DB.Exec("PRAGMA optimize")
		}
	}
	databaseFS, ok := &DatabaseFS{}, false
	switch v := nbrew.FS.(type) {
	case interface{ As(any) bool }:
		ok = v.As(&databaseFS)
	}
	if ok {
		if databaseFS.Dialect == "sqlite" {
			databaseFS.DB.Exec("PRAGMA optimize")
		}
	}
	return nil
}

// User represents a user in the users table.
type User struct {
	// UserID uniquely identifies a user. It cannot be changed.
	UserID ID

	// Username uniquely identifies a user. It can be changed.
	Username string

	// Email uniquely identifies a user. It can be changed.
	Email string

	// TimezoneOffsetSeconds represents a user's preferred timezone offset in
	// seconds.
	TimezoneOffsetSeconds int

	// Is not empty, DisableReason is the reason why the user's account is
	// marked as disabled.
	DisableReason string

	// SiteLimit is the limit on the number of sites the user can create.
	SiteLimit int64

	// StorageLimit is the limit on the amount of storage the user can use.
	StorageLimit int64

	// UserFlags are various properties on a user that may be enabled or
	// disabled e.g. UploadImages.
	UserFlags map[string]bool
}

type contextKey struct{}

// LoggerKey is the key used by notebrew for setting and getting a logger from
// the request context.
var LoggerKey = &contextKey{}

// GetLogger is a syntactic sugar operation for getting a request-specific
// logger from the context, or else it returns the default logger.
func (nbrew *Notebrew) GetLogger(ctx context.Context) *slog.Logger {
	if logger, ok := ctx.Value(LoggerKey).(*slog.Logger); ok {
		return logger
	}
	return nbrew.Logger
}

// SetFlashSession writes a value into the user's flash session.
func (nbrew *Notebrew) SetFlashSession(w http.ResponseWriter, r *http.Request, value any) error {
	buf := bufPool.Get().(*bytes.Buffer)
	defer func() {
		if buf.Cap() <= maxPoolableBufferCapacity {
			buf.Reset()
			bufPool.Put(buf)
		}
	}()
	encoder := json.NewEncoder(buf)
	encoder.SetEscapeHTML(false)
	err := encoder.Encode(&value)
	if err != nil {
		return stacktrace.New(err)
	}
	cookie := &http.Cookie{
		Path:     "/",
		Name:     "flash",
		Secure:   r.TLS != nil,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
	if developerMode {
		os.Stderr.WriteString(buf.String())
	}
	if nbrew.DB == nil {
		cookie.Value = base64.URLEncoding.EncodeToString(buf.Bytes())
	} else {
		var flashTokenBytes [8 + 16]byte
		binary.BigEndian.PutUint64(flashTokenBytes[:8], uint64(time.Now().Unix()))
		_, err := rand.Read(flashTokenBytes[8:])
		if err != nil {
			return stacktrace.New(err)
		}
		var flashTokenHash [8 + blake2b.Size256]byte
		checksum := blake2b.Sum256(flashTokenBytes[8:])
		copy(flashTokenHash[:8], flashTokenBytes[:8])
		copy(flashTokenHash[8:], checksum[:])
		_, err = sq.Exec(r.Context(), nbrew.DB, sq.Query{
			Dialect: nbrew.Dialect,
			Format:  "INSERT INTO flash (flash_token_hash, data) VALUES ({flashTokenHash}, {data})",
			Values: []any{
				sq.BytesParam("flashTokenHash", flashTokenHash[:]),
				sq.StringParam("data", strings.TrimSpace(buf.String())),
			},
		})
		if err != nil {
			return stacktrace.New(err)
		}
		cookie.Value = strings.TrimLeft(hex.EncodeToString(flashTokenBytes[:]), "0")
	}
	http.SetCookie(w, cookie)
	return nil
}

// GetFlashSession retrieves a value from the user's flash session, unmarshals
// it into the valuePtr and then deletes the session. It returns a boolean
// result indicating if a flash session was retrieved.
func (nbrew *Notebrew) GetFlashSession(w http.ResponseWriter, r *http.Request, valuePtr any) (ok bool, err error) {
	cookie, _ := r.Cookie("flash")
	if cookie == nil {
		return false, nil
	}
	http.SetCookie(w, &http.Cookie{
		Path:     "/",
		Name:     "flash",
		Value:    "0",
		MaxAge:   -1,
		Secure:   r.TLS != nil,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	var data []byte
	if nbrew.DB == nil {
		data, err = base64.URLEncoding.DecodeString(cookie.Value)
		if err != nil {
			return false, nil
		}
	} else {
		flashToken, err := hex.DecodeString(fmt.Sprintf("%048s", cookie.Value))
		if err != nil {
			return false, nil
		}
		creationTime := time.Unix(int64(binary.BigEndian.Uint64(flashToken[:8])), 0).UTC()
		if time.Now().Sub(creationTime) > 5*time.Minute {
			return false, nil
		}
		var flashTokenHash [8 + blake2b.Size256]byte
		checksum := blake2b.Sum256(flashToken[8:])
		copy(flashTokenHash[:8], flashToken[:8])
		copy(flashTokenHash[8:], checksum[:])
		switch nbrew.Dialect {
		case "sqlite", "postgres":
			data, err = sq.FetchOne(r.Context(), nbrew.DB, sq.Query{
				Dialect: nbrew.Dialect,
				Format:  "DELETE FROM flash WHERE flash_token_hash = {flashTokenHash} RETURNING {*}",
				Values: []any{
					sq.BytesParam("flashTokenHash", flashTokenHash[:]),
				},
			}, func(row *sq.Row) []byte {
				return row.Bytes(nil, "data")
			})
			if err != nil {
				if errors.Is(err, sql.ErrNoRows) {
					return false, nil
				}
				return false, stacktrace.New(err)
			}
		default:
			data, err = sq.FetchOne(r.Context(), nbrew.DB, sq.Query{
				Dialect: nbrew.Dialect,
				Format:  "SELECT {*} FROM flash WHERE flash_token_hash = {flashTokenHash}",
				Values: []any{
					sq.BytesParam("flashTokenHash", flashTokenHash[:]),
				},
			}, func(row *sq.Row) []byte {
				return row.Bytes(nil, "data")
			})
			if err != nil {
				if errors.Is(err, sql.ErrNoRows) {
					return false, nil
				}
				return false, stacktrace.New(err)
			}
			_, err = sq.Exec(r.Context(), nbrew.DB, sq.Query{
				Dialect: nbrew.Dialect,
				Format:  "DELETE FROM flash WHERE flash_token_hash = {flashTokenHash}",
				Values: []any{
					sq.BytesParam("flashTokenHash", flashTokenHash[:]),
				},
			})
			if err != nil {
				return false, stacktrace.New(err)
			}
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	err = decoder.Decode(valuePtr)
	if err != nil {
		return true, stacktrace.New(err)
	}
	return true, nil
}

// urlReplacer escapes special characters in a URL for http.Redirect.
var urlReplacer = strings.NewReplacer("#", "%23", "%", "%25")

// Crockford Base32 encoding.
var base32Encoding = base32.NewEncoding("0123456789abcdefghjkmnpqrstvwxyz").WithPadding(base32.NoPadding)

// markdownTextOnly takes in a markdown snippet and extracts the text only,
// removing any markup.
func markdownTextOnly(parser parser.Parser, src []byte) string {
	buf := bufPool.Get().(*bytes.Buffer)
	defer func() {
		if buf.Cap() <= maxPoolableBufferCapacity {
			buf.Reset()
			bufPool.Put(buf)
		}
	}()
	var node ast.Node
	nodes := []ast.Node{
		parser.Parse(text.NewReader(src)),
	}
	for len(nodes) > 0 {
		node, nodes = nodes[len(nodes)-1], nodes[:len(nodes)-1]
		switch node := node.(type) {
		case nil:
			continue
		case *ast.Image, *ast.CodeBlock, *ast.FencedCodeBlock, *ast.HTMLBlock:
			nodes = append(nodes, node.NextSibling())
		case *ast.Text:
			buf.Write(node.Text(src))
			nodes = append(nodes, node.NextSibling(), node.FirstChild())
		default:
			nodes = append(nodes, node.NextSibling(), node.FirstChild())
		}
	}
	// Manually escape backslashes (goldmark may be able to do this,
	// investigate).
	var b strings.Builder
	b.Grow(buf.Len())
	output := buf.Bytes()
	// Jump to the location of each backslash found in the output.
	for i := bytes.IndexByte(output, '\\'); i >= 0; i = bytes.IndexByte(output, '\\') {
		b.Write(output[:i])
		char, width := utf8.DecodeRune(output[i+1:])
		if char != utf8.RuneError {
			b.WriteRune(char)
		}
		output = output[i+1+width:]
	}
	b.Write(output)
	return b.String()
}

// isURLUnsafe is a rune-to-bool mapping indicating if a rune is unsafe for
// URLs.
var isURLUnsafe = [...]bool{
	' ': true, '!': true, '"': true, '#': true, '$': true, '%': true, '&': true, '\'': true,
	'(': true, ')': true, '*': true, '+': true, ',': true, '/': true, ':': true, ';': true,
	'<': true, '>': true, '=': true, '?': true, '[': true, ']': true, '\\': true, '^': true,
	'`': true, '{': true, '}': true, '|': true, '~': true,
}

// urlSafe sanitizes a string to make it url-safe by removing any url-unsafe
// characters.
func urlSafe(s string) string {
	s = strings.TrimSpace(s)
	var count int
	var b strings.Builder
	b.Grow(len(s))
	for _, char := range s {
		if count >= 80 {
			break
		}
		if char == ' ' {
			b.WriteRune('-')
			count++
			continue
		}
		if char == '-' || (char >= '0' && char <= '9') || (char >= 'a' && char <= 'z') {
			b.WriteRune(char)
			count++
			continue
		}
		if char >= 'A' && char <= 'Z' {
			b.WriteRune(unicode.ToLower(char))
			count++
			continue
		}
		n := int(char)
		if n < len(isURLUnsafe) && isURLUnsafe[n] {
			continue
		}
		b.WriteRune(char)
		count++
	}
	return strings.Trim(b.String(), ".")
}

// filenameReplacementChars is a map of filename-unsafe runes to their
// filename-safe replacements. Reference: https://stackoverflow.com/a/31976060.
var filenameReplacementChars = [...]rune{
	'<':  '＜', // U+FF1C, FULLWIDTH LESS-THAN SIGN
	'>':  '＞', // U+FF1E, FULLWIDTH GREATER-THAN SIGN
	':':  '꞉', // U+A789, MODIFIER LETTER COLON
	'"':  '″', // U+2033, DOUBLE PRIME
	'/':  '／', // U+FF0F, FULLWIDTH SOLIDUS
	'\\': '＼', // U+FF3C, FULLWIDTH REVERSE SOLIDUS
	'|':  '│', // U+2502, BOX DRAWINGS LIGHT VERTICAL
	'?':  '？', // U+FF1F, FULLWIDTH QUESTION MARK
	'*':  '∗', // U+2217, ASTERISK OPERATOR
	// NOTE: Hex is technically not filename-unsafe, but is does not get
	// properly escaped in URLs because it gets mistaken as the fragment
	// identifier so we need to replace it too.
	'#': '＃', // U+FF03, FULLWIDTH NUMBER SIGN
}

// filenameSafe makes a string safe for use in filenames by replacing any
// filename-unsafe characters to their filename-safe equivalents.
func filenameSafe(s string) string {
	s = strings.TrimSpace(s)
	var b strings.Builder
	b.Grow(len(s))
	for _, char := range s {
		if char >= 0 && char <= 31 {
			continue
		}
		n := int(char)
		if n >= len(filenameReplacementChars) {
			b.WriteRune(char)
			continue
		}
		replacementChar := filenameReplacementChars[n]
		if replacementChar == 0 {
			b.WriteRune(char)
			continue
		}
		b.WriteRune(replacementChar)
	}
	return strings.Trim(b.String(), ".")
}

var hashPool = sync.Pool{
	New: func() any {
		hash, err := blake2b.New256(nil)
		if err != nil {
			panic(err)
		}
		return hash
	},
}

var readerPool = sync.Pool{
	New: func() any {
		return bufio.NewReaderSize(nil, 512)
	},
}

// ExecuteTemplate renders a given template with the given data into the
// ResponseWriter, but it first buffers the HTML output so that it can detect
// if any template errors occurred, and if so return 500 Internal Server Error
// instead. Additionally, it does on-the-fly gzipping of the HTML response as
// well as calculating the ETag so that the HTML may be cached by the client.
func (nbrew *Notebrew) ExecuteTemplate(w http.ResponseWriter, r *http.Request, tmpl *template.Template, data any) {
	buf := bufPool.Get().(*bytes.Buffer)
	defer func() {
		if buf.Cap() <= maxPoolableBufferCapacity {
			buf.Reset()
			bufPool.Put(buf)
		}
	}()
	hasher := hashPool.Get().(hash.Hash)
	defer func() {
		hasher.Reset()
		hashPool.Put(hasher)
	}()
	multiWriter := io.MultiWriter(buf, hasher)
	gzipWriter := gzipWriterPool.Get().(*gzip.Writer)
	gzipWriter.Reset(multiWriter)
	defer func() {
		gzipWriter.Reset(io.Discard)
		gzipWriterPool.Put(gzipWriter)
	}()
	err := tmpl.Execute(gzipWriter, data)
	if err != nil {
		nbrew.GetLogger(r.Context()).Error(err.Error())
		fmt.Printf(fmt.Sprintf("%#v", data))
		nbrew.InternalServerError(w, r, err)
		return
	}
	err = gzipWriter.Close()
	if err != nil {
		nbrew.GetLogger(r.Context()).Error(err.Error())
		nbrew.InternalServerError(w, r, err)
		return
	}
	var b [blake2b.Size256]byte
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Encoding", "gzip")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("ETag", `"`+hex.EncodeToString(hasher.Sum(b[:0]))+`"`)
	http.ServeContent(w, r, "", time.Time{}, bytes.NewReader(buf.Bytes()))
}

// ContentBaseURL returns the content site's base URL (starting with http:// or
// https://) for a given site prefix.
func (nbrew *Notebrew) ContentBaseURL(sitePrefix string) string {
	if strings.Contains(sitePrefix, ".") {
		return "https://" + sitePrefix
	}
	if nbrew.CMSDomain == "localhost" || strings.HasPrefix(nbrew.CMSDomain, "localhost:") {
		if sitePrefix != "" {
			return "http://" + strings.TrimPrefix(sitePrefix, "@") + "." + nbrew.CMSDomain
		}
		return "http://" + nbrew.CMSDomain
	}
	if sitePrefix != "" {
		return "https://" + strings.TrimPrefix(sitePrefix, "@") + "." + nbrew.ContentDomain
	}
	return "https://" + nbrew.ContentDomain
}

// GetReferer is like (*http.Request).Referer() except it returns an empty
// string if the referer is the same as the current page's URL so that the user
// doesn't keep pressing back to the same page.
func (nbrew *Notebrew) GetReferer(r *http.Request) string {
	// https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referer
	//
	// "The Referer header can contain an origin, path, and querystring, and
	// may not contain URL fragments (i.e. #section) or username:password
	// information."
	referer := r.Referer()
	uri := *r.URL
	if r.TLS == nil {
		uri.Scheme = "http"
	} else {
		uri.Scheme = "https"
	}
	uri.Host = r.Host
	uri.Fragment = ""
	uri.User = nil
	if referer == uri.String() {
		return ""
	}
	return referer
}

// errorTemplate is the template used for all error responses i.e.
// InternalServerError, NotFound, NotAuthorized, etc. It is parsed once at
// package initialization time so any changes to the error template require
// recompiling the notebrew binary.
var errorTemplate = template.Must(template.
	New("error.html").
	Funcs(map[string]any{
		"safeHTML": func(v any) template.HTML {
			if str, ok := v.(string); ok {
				return template.HTML(str)
			}
			return ""
		},
	}).
	ParseFS(RuntimeFS, "embed/error.html"),
)

// HumanReadableFileSize returns a human readable file size of an int64 size in
// bytes.
func HumanReadableFileSize(size int64) string {
	// https://yourbasic.org/golang/formatting-byte-size-to-human-readable-format/
	if size < 0 {
		return ""
	}
	const unit = 1000
	if size < unit {
		return fmt.Sprintf("%d B", size)
	}
	div, exp := int64(unit), 0
	for n := size / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(size)/float64(div), "kMGTPE"[exp])
}

// BadRequest indicates that something was wrong with the request data.
func (nbrew *Notebrew) BadRequest(w http.ResponseWriter, r *http.Request, serverErr error) {
	var message string
	var maxBytesErr *http.MaxBytesError
	if errors.As(serverErr, &maxBytesErr) {
		message = "payload is too big (max " + HumanReadableFileSize(maxBytesErr.Limit) + ")"
	} else {
		contentType, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if contentType == "application/json" {
			if serverErr == io.EOF {
				message = "missing JSON body"
			} else if serverErr == io.ErrUnexpectedEOF {
				message = "malformed JSON"
			} else {
				message = serverErr.Error()
			}
		} else {
			message = serverErr.Error()
		}
	}
	if r.Form.Has("api") {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		if r.Method == "HEAD" {
			return
		}
		encoder := json.NewEncoder(w)
		encoder.SetIndent("", "  ")
		encoder.SetEscapeHTML(false)
		err := encoder.Encode(map[string]any{
			"error":   "BadRequest",
			"message": message,
		})
		if err != nil {
			nbrew.GetLogger(r.Context()).Error(err.Error())
		}
		return
	}
	buf := bufPool.Get().(*bytes.Buffer)
	defer func() {
		if buf.Cap() <= maxPoolableBufferCapacity {
			buf.Reset()
			bufPool.Put(buf)
		}
	}()
	err := errorTemplate.Execute(buf, map[string]any{
		"Title":    `400 bad request`,
		"Headline": "400 bad request",
		"Byline":   message,
	})
	if err != nil {
		nbrew.GetLogger(r.Context()).Error(err.Error())
		http.Error(w, "BadRequest: "+message, http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Security-Policy", nbrew.ContentSecurityPolicy)
	w.WriteHeader(http.StatusBadRequest)
	if r.Method == "HEAD" {
		return
	}
	buf.WriteTo(w)
}

// NotAuthenticated indicates that the user is not logged in.
func (nbrew *Notebrew) NotAuthenticated(w http.ResponseWriter, r *http.Request) {
	if r.Form.Has("api") {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusUnauthorized)
		if r.Method == "HEAD" {
			return
		}
		encoder := json.NewEncoder(w)
		encoder.SetIndent("", "  ")
		encoder.SetEscapeHTML(false)
		err := encoder.Encode(map[string]any{
			"error": "NotAuthenticated",
		})
		if err != nil {
			nbrew.GetLogger(r.Context()).Error(err.Error())
		}
		return
	}
	buf := bufPool.Get().(*bytes.Buffer)
	defer func() {
		if buf.Cap() <= maxPoolableBufferCapacity {
			buf.Reset()
			bufPool.Put(buf)
		}
	}()
	var query string
	if r.Method == "GET" {
		if r.URL.RawQuery != "" {
			query = "?redirect=" + url.QueryEscape(r.URL.Path+"?"+r.URL.RawQuery)
		} else {
			query = "?redirect=" + url.QueryEscape(r.URL.Path)
		}
	}
	err := errorTemplate.Execute(buf, map[string]any{
		"Title":    "401 unauthorized",
		"Headline": "401 unauthorized",
		"Byline":   fmt.Sprintf("You are not authenticated, please <a href='/users/login/%s'>log in</a>.", query),
	})
	if err != nil {
		nbrew.GetLogger(r.Context()).Error(err.Error())
		http.Error(w, "NotAuthenticated", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Security-Policy", nbrew.ContentSecurityPolicy)
	w.WriteHeader(http.StatusUnauthorized)
	if r.Method == "HEAD" {
		return
	}
	buf.WriteTo(w)
}

// NotAuthorized indicates that the user is logged in, but is not authorized to
// view the current page or perform the current action.
func (nbrew *Notebrew) NotAuthorized(w http.ResponseWriter, r *http.Request) {
	if r.Form.Has("api") {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusForbidden)
		if r.Method == "HEAD" {
			return
		}
		encoder := json.NewEncoder(w)
		encoder.SetIndent("", "  ")
		encoder.SetEscapeHTML(false)
		err := encoder.Encode(map[string]any{
			"error": "NotAuthorized",
		})
		if err != nil {
			nbrew.GetLogger(r.Context()).Error(err.Error())
		}
		return
	}
	buf := bufPool.Get().(*bytes.Buffer)
	defer func() {
		if buf.Cap() <= maxPoolableBufferCapacity {
			buf.Reset()
			bufPool.Put(buf)
		}
	}()
	var byline string
	if r.Method == "GET" || r.Method == "HEAD" {
		byline = "You do not have permission to view this page (try logging in to a different account)."
	} else {
		byline = "You do not have permission to perform that action (try logging in to a different account)."
	}
	err := errorTemplate.Execute(buf, map[string]any{
		"Referer":  nbrew.GetReferer(r),
		"Title":    "403 forbidden",
		"Headline": "403 forbidden",
		"Byline":   byline,
	})
	if err != nil {
		nbrew.GetLogger(r.Context()).Error(err.Error())
		http.Error(w, "NotAuthorized", http.StatusForbidden)
		return
	}
	w.Header().Set("Content-Security-Policy", nbrew.ContentSecurityPolicy)
	w.WriteHeader(http.StatusForbidden)
	if r.Method == "HEAD" {
		return
	}
	buf.WriteTo(w)
}

// NotFound indicates that a URL does not exist.
func (nbrew *Notebrew) NotFound(w http.ResponseWriter, r *http.Request) {
	if r.Form.Has("api") {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusNotFound)
		if r.Method == "HEAD" {
			return
		}
		encoder := json.NewEncoder(w)
		encoder.SetIndent("", "  ")
		encoder.SetEscapeHTML(false)
		err := encoder.Encode(map[string]any{
			"error": "NotFound",
		})
		if err != nil {
			nbrew.GetLogger(r.Context()).Error(err.Error())
		}
		return
	}
	buf := bufPool.Get().(*bytes.Buffer)
	defer func() {
		if buf.Cap() <= maxPoolableBufferCapacity {
			buf.Reset()
			bufPool.Put(buf)
		}
	}()
	err := errorTemplate.Execute(buf, map[string]any{
		"Referer":  nbrew.GetReferer(r),
		"Title":    "404 not found",
		"Headline": "404 not found",
		"Byline":   "The page you are looking for does not exist.",
	})
	if err != nil {
		nbrew.GetLogger(r.Context()).Error(err.Error())
		http.Error(w, "NotFound", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Security-Policy", nbrew.ContentSecurityPolicy)
	w.WriteHeader(http.StatusNotFound)
	if r.Method == "HEAD" {
		return
	}
	buf.WriteTo(w)
}

// MethodNotAllowed indicates that the request method is not allowed.
func (nbrew *Notebrew) MethodNotAllowed(w http.ResponseWriter, r *http.Request) {
	if r.Form.Has("api") {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusMethodNotAllowed)
		if r.Method == "HEAD" {
			return
		}
		encoder := json.NewEncoder(w)
		encoder.SetIndent("", "  ")
		encoder.SetEscapeHTML(false)
		err := encoder.Encode(map[string]any{
			"error":  "MethodNotAllowed",
			"method": r.Method,
		})
		if err != nil {
			nbrew.GetLogger(r.Context()).Error(err.Error())
		}
		return
	}
	buf := bufPool.Get().(*bytes.Buffer)
	defer func() {
		if buf.Cap() <= maxPoolableBufferCapacity {
			buf.Reset()
			bufPool.Put(buf)
		}
	}()
	err := errorTemplate.Execute(buf, map[string]any{
		"Referer":  nbrew.GetReferer(r),
		"Title":    "405 method not allowed",
		"Headline": "405 method not allowed: " + r.Method,
	})
	if err != nil {
		nbrew.GetLogger(r.Context()).Error(err.Error())
		http.Error(w, "NotFound", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Security-Policy", nbrew.ContentSecurityPolicy)
	w.WriteHeader(http.StatusMethodNotAllowed)
	if r.Method == "HEAD" {
		return
	}
	buf.WriteTo(w)
}

// UnsupportedContentType indicates that the request did not send a supported
// Content-Type.
func (nbrew *Notebrew) UnsupportedContentType(w http.ResponseWriter, r *http.Request) {
	contentType := r.Header.Get("Content-Type")
	var message string
	if contentType == "" {
		message = "missing Content-Type"
	} else {
		message = "unsupported Content-Type: " + contentType
	}
	if r.Form.Has("api") {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusUnsupportedMediaType)
		if r.Method == "HEAD" {
			return
		}
		encoder := json.NewEncoder(w)
		encoder.SetIndent("", "  ")
		encoder.SetEscapeHTML(false)
		err := encoder.Encode(map[string]any{
			"error":   "UnsupportedMediaType",
			"message": message,
		})
		if err != nil {
			nbrew.GetLogger(r.Context()).Error(err.Error())
		}
		return
	}
	buf := bufPool.Get().(*bytes.Buffer)
	defer func() {
		if buf.Cap() <= maxPoolableBufferCapacity {
			buf.Reset()
			bufPool.Put(buf)
		}
	}()
	err := errorTemplate.Execute(buf, map[string]any{
		"Referer":  nbrew.GetReferer(r),
		"Title":    "415 unsupported media type",
		"Headline": message,
	})
	if err != nil {
		nbrew.GetLogger(r.Context()).Error(err.Error())
		http.Error(w, "UnsupportedMediaType "+message, http.StatusUnsupportedMediaType)
		return
	}
	w.Header().Set("Content-Security-Policy", nbrew.ContentSecurityPolicy)
	w.WriteHeader(http.StatusUnsupportedMediaType)
	if r.Method == "HEAD" {
		return
	}
	buf.WriteTo(w)
}

// InternalServerError is a catch-all handler for catching server errors and
// displaying it to the user.
//
// This includes the error message as well as the stack trace and notebrew
// version, in hopes that a user will be able to give developers the detailed
// error and trace in order to diagnose the problem faster.
func (nbrew *Notebrew) InternalServerError(w http.ResponseWriter, r *http.Request, serverErr error) {
	if serverErr == nil {
		if r.Method == "HEAD" {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
		return
	}
	var errmsg string
	var callers []string
	var stackTraceErr *stacktrace.Error
	if errors.As(serverErr, &stackTraceErr) {
		errmsg = stackTraceErr.Err.Error()
		callers = stackTraceErr.Callers
	} else {
		errmsg = serverErr.Error()
		var pc [30]uintptr
		n := runtime.Callers(2, pc[:]) // skip runtime.Callers + InternalServerError
		callers = make([]string, 0, n)
		frames := runtime.CallersFrames(pc[:n])
		for frame, more := frames.Next(); more; frame, more = frames.Next() {
			callers = append(callers, frame.File+":"+strconv.Itoa(frame.Line))
		}
	}
	isDeadlineExceeded := errors.Is(serverErr, context.DeadlineExceeded)
	isCanceled := errors.Is(serverErr, context.Canceled)
	if nbrew.ErrorlogConfig.Email != "" && nbrew.Mailer != nil && !isDeadlineExceeded && !isCanceled {
		nbrew.BaseCtxWaitGroup.Add(1)
		go func() {
			defer func() {
				if v := recover(); v != nil {
					fmt.Println(stacktrace.New(fmt.Errorf("panic: %v", v)))
				}
			}()
			defer nbrew.BaseCtxWaitGroup.Done()
			var b strings.Builder
			b.WriteString(nbrew.CMSDomain + ": internal server error")
			b.WriteString("\r\n")
			b.WriteString("\r\n" + errmsg)
			b.WriteString("\r\n")
			b.WriteString("\r\nstack trace:")
			for _, caller := range callers {
				b.WriteString("\r\n" + caller)
			}
			b.WriteString("\r\n")
			b.WriteString("\r\ngit commit: " + Version)
			mail := Mail{
				MailFrom: nbrew.MailFrom,
				RcptTo:   nbrew.ErrorlogConfig.Email,
				Headers: []string{
					"Subject", "notebrew: " + nbrew.CMSDomain + ": internal server error: " + errmsg,
					"Content-Type", "text/plain; charset=utf-8",
				},
				Body: strings.NewReader(b.String()),
			}
			select {
			case <-nbrew.BaseCtx.Done():
			case nbrew.Mailer.C <- mail:
			}
		}()
	}
	if r.Form.Has("api") {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusInternalServerError)
		if r.Method == "HEAD" {
			return
		}
		encoder := json.NewEncoder(w)
		encoder.SetIndent("", "  ")
		encoder.SetEscapeHTML(false)
		err := encoder.Encode(map[string]any{
			"error":   "InternalServerError",
			"message": errmsg,
			"callers": callers,
			"version": Version,
		})
		if err != nil {
			nbrew.GetLogger(r.Context()).Error(err.Error())
		}
		return
	}
	buf := bufPool.Get().(*bytes.Buffer)
	defer func() {
		if buf.Cap() <= maxPoolableBufferCapacity {
			buf.Reset()
			bufPool.Put(buf)
		}
	}()
	var data map[string]any
	if isDeadlineExceeded {
		data = map[string]any{
			"Referer":  nbrew.GetReferer(r),
			"Title":    "deadline exceeded",
			"Headline": "The server took too long to process your request.",
			"Details":  errmsg,
			"Callers":  callers,
			"Version":  Version,
		}
	} else {
		data = map[string]any{
			"Referer":  nbrew.GetReferer(r),
			"Title":    "500 internal server error",
			"Headline": "500 internal server error",
			"Byline":   "There's a bug with notebrew.",
			"Details":  errmsg,
			"Callers":  callers,
			"Version":  Version,
		}
	}
	err := errorTemplate.Execute(buf, data)
	if err != nil {
		nbrew.GetLogger(r.Context()).Error(err.Error())
		http.Error(w, "ServerError", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Security-Policy", nbrew.ContentSecurityPolicy)
	w.WriteHeader(http.StatusInternalServerError)
	if r.Method == "HEAD" {
		return
	}
	buf.WriteTo(w)
}

// ServeFile serves a given file (in the form of an io.Reader). It applies a
// potential list of optimizations such as gzipping the response, handling
// Range requests, calculating the ETag and setting the Cache-Control header.
func ServeFile(w http.ResponseWriter, r *http.Request, name string, size int64, fileType FileType, reader io.Reader, cacheControl string) {
	// If max-age is present in Cache-Control, don't set the ETag because that
	// would override max-age. https://stackoverflow.com/a/51257030
	hasMaxAge := strings.Contains(cacheControl, "max-age=")
	// TODO: for all the cases where we fall back to io.Copy instead of using
	// http.ServeContent, think about manually handling range requests (as
	// http.ServeContent does) so that clients (e.g. internet download
	// managers) have the ability to download a file in multiple parts.

	if !fileType.Has(AttributeGzippable) {
		if readSeeker, ok := reader.(io.ReadSeeker); ok {
			if hasMaxAge {
				w.Header().Set("Content-Type", fileType.ContentType)
				w.Header().Set("Cache-Control", cacheControl)
				if fileType.Has(AttributeAttachment) {
					w.Header().Set("Content-Disposition", "attachment; filename="+strconv.Quote(name))
				}
				http.ServeContent(w, r, "", time.Time{}, readSeeker)
				return
			}
			hasher := hashPool.Get().(hash.Hash)
			defer func() {
				hasher.Reset()
				hashPool.Put(hasher)
			}()
			_, err := io.Copy(hasher, reader)
			if err != nil {
				logger, ok := r.Context().Value(LoggerKey).(*slog.Logger)
				if !ok {
					logger = slog.Default()
				}
				logger.Error(stacktrace.New(err).Error())
				http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
				return
			}
			_, err = readSeeker.Seek(0, io.SeekStart)
			if err != nil {
				logger, ok := r.Context().Value(LoggerKey).(*slog.Logger)
				if !ok {
					logger = slog.Default()
				}
				logger.Error(stacktrace.New(err).Error())
				http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
				return
			}
			var b [blake2b.Size256]byte
			w.Header().Set("Content-Type", fileType.ContentType)
			w.Header().Set("Cache-Control", cacheControl)
			w.Header().Set("ETag", `"`+hex.EncodeToString(hasher.Sum(b[:0]))+`"`)
			if fileType.Has(AttributeAttachment) {
				w.Header().Set("Content-Disposition", "attachment; filename="+strconv.Quote(name))
			}
			http.ServeContent(w, r, "", time.Time{}, readSeeker)
			return
		}
		w.Header().Set("Content-Type", fileType.ContentType)
		w.Header().Set("Cache-Control", cacheControl)
		if fileType.Has(AttributeAttachment) {
			w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
			w.Header().Set("Content-Disposition", "attachment; filename="+strconv.Quote(name))
		}
		if r.Method == "HEAD" {
			w.WriteHeader(http.StatusOK)
			return
		}
		io.Copy(w, reader)
		return
	}

	if databaseFile, ok := reader.(*DatabaseFile); ok {
		// If file is a DatabaseFile that is gzippable and is not fulltext
		// indexed, its contents are already gzipped. We can reach directly
		// into its buffer and skip the gzipping step.
		if databaseFile.fileType.Has(AttributeGzippable) && !databaseFile.isFulltextIndexed {
			if hasMaxAge {
				w.Header().Set("Content-Encoding", "gzip")
				w.Header().Set("Content-Type", fileType.ContentType)
				w.Header().Set("Cache-Control", cacheControl)
				if fileType.Has(AttributeAttachment) {
					w.Header().Set("Content-Disposition", "attachment; filename="+strconv.Quote(name))
				}
				http.ServeContent(w, r, "", time.Time{}, bytes.NewReader(databaseFile.buf.Bytes()))
				return
			}
			hasher := hashPool.Get().(hash.Hash)
			defer func() {
				hasher.Reset()
				hashPool.Put(hasher)
			}()
			_, err := hasher.Write(databaseFile.buf.Bytes())
			if err != nil {
				logger, ok := r.Context().Value(LoggerKey).(*slog.Logger)
				if !ok {
					logger = slog.Default()
				}
				logger.Error(stacktrace.New(err).Error())
				http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
				return
			}
			var b [blake2b.Size256]byte
			w.Header().Set("Content-Encoding", "gzip")
			w.Header().Set("Content-Type", fileType.ContentType)
			w.Header().Set("Cache-Control", cacheControl)
			w.Header().Set("ETag", `"`+hex.EncodeToString(hasher.Sum(b[:0]))+`"`)
			if fileType.Has(AttributeAttachment) {
				w.Header().Set("Content-Disposition", "attachment; filename="+strconv.Quote(name))
			}
			http.ServeContent(w, r, "", time.Time{}, bytes.NewReader(databaseFile.buf.Bytes()))
			return
		}
	}

	// If file is small enough and we want the ETag, we can buffer the entire
	// file into memory, calculate its ETag and serve.
	if size <= 1<<20 /* 1 MB */ && !hasMaxAge {
		hasher := hashPool.Get().(hash.Hash)
		defer func() {
			hasher.Reset()
			hashPool.Put(hasher)
		}()
		var buf *bytes.Buffer
		// gzip will at least halve the size of what needs to be buffered
		gzippedSize := size >> 1
		if gzippedSize > maxPoolableBufferCapacity {
			buf = bytes.NewBuffer(make([]byte, 0, size))
		} else {
			buf = bufPool.Get().(*bytes.Buffer)
			defer func() {
				buf.Reset()
				bufPool.Put(buf)
			}()
		}
		multiWriter := io.MultiWriter(buf, hasher)
		gzipWriter := gzipWriterPool.Get().(*gzip.Writer)
		gzipWriter.Reset(multiWriter)
		defer func() {
			gzipWriter.Reset(io.Discard)
			gzipWriterPool.Put(gzipWriter)
		}()
		_, err := io.Copy(gzipWriter, reader)
		if err != nil {
			logger, ok := r.Context().Value(LoggerKey).(*slog.Logger)
			if !ok {
				logger = slog.Default()
			}
			logger.Error(stacktrace.New(err).Error())
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
			return
		}
		err = gzipWriter.Close()
		if err != nil {
			logger, ok := r.Context().Value(LoggerKey).(*slog.Logger)
			if !ok {
				logger = slog.Default()
			}
			logger.Error(stacktrace.New(err).Error())
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
			return
		}
		var b [blake2b.Size256]byte
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Type", fileType.ContentType)
		w.Header().Set("Cache-Control", cacheControl)
		w.Header().Set("ETag", `"`+hex.EncodeToString(hasher.Sum(b[:0]))+`"`)
		if fileType.Has(AttributeAttachment) {
			w.Header().Set("Content-Disposition", "attachment; filename="+strconv.Quote(name))
		}
		http.ServeContent(w, r, "", time.Time{}, bytes.NewReader(buf.Bytes()))
		return
	}

	w.Header().Set("Content-Encoding", "gzip")
	w.Header().Set("Content-Type", fileType.ContentType)
	w.Header().Set("Cache-Control", cacheControl)
	if fileType.Has(AttributeAttachment) {
		w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
		w.Header().Set("Content-Disposition", "attachment; filename="+strconv.Quote(name))
	}
	gzipWriter := gzipWriterPool.Get().(*gzip.Writer)
	gzipWriter.Reset(w)
	defer func() {
		gzipWriter.Reset(io.Discard)
		gzipWriterPool.Put(gzipWriter)
	}()
	if r.Method == "HEAD" {
		w.WriteHeader(http.StatusOK)
		return
	}
	io.Copy(gzipWriter, reader)
	gzipWriter.Close()
}

// ErrStorageLimitExceeded is the error returned by an operation if a user
// exceeded their storage limit during the operation.
var ErrStorageLimitExceeded = fmt.Errorf("storage limit exceeded")

// StorageLimitExceeded indicates that the user exceeded their storage limit.
func (nbrew *Notebrew) StorageLimitExceeded(w http.ResponseWriter, r *http.Request) {
	if r.Form.Has("api") {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusInsufficientStorage)
		if r.Method == "HEAD" {
			return
		}
		encoder := json.NewEncoder(w)
		encoder.SetIndent("", "  ")
		encoder.SetEscapeHTML(false)
		err := encoder.Encode(map[string]any{
			"error": "StorageLimitExceeded",
		})
		if err != nil {
			nbrew.GetLogger(r.Context()).Error(err.Error())
		}
		return
	}
	buf := bufPool.Get().(*bytes.Buffer)
	defer func() {
		if buf.Cap() <= maxPoolableBufferCapacity {
			buf.Reset()
			bufPool.Put(buf)
		}
	}()
	err := errorTemplate.Execute(buf, map[string]any{
		"Referer":  r.Referer(),
		"Title":    "507 insufficient storage",
		"Headline": "507 insufficient storage",
		"Byline":   "You have exceeded your storage limit.",
	})
	if err != nil {
		nbrew.GetLogger(r.Context()).Error(err.Error())
		http.Error(w, "StorageLimitExceeded", http.StatusInsufficientStorage)
		return
	}
	w.Header().Set("Content-Security-Policy", nbrew.ContentSecurityPolicy)
	w.WriteHeader(http.StatusInsufficientStorage)
	if r.Method == "HEAD" {
		return
	}
	buf.WriteTo(w)
}

// AccountDisabled indicates that a user's account is disabled.
func (nbrew *Notebrew) AccountDisabled(w http.ResponseWriter, r *http.Request, disableReason string) {
	if r.Form.Has("api") {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusForbidden)
		encoder := json.NewEncoder(w)
		encoder.SetIndent("", "  ")
		encoder.SetEscapeHTML(false)
		err := encoder.Encode(map[string]any{
			"error":         "AccountDisabled",
			"disableReason": disableReason,
		})
		if err != nil {
			nbrew.GetLogger(r.Context()).Error(err.Error())
		}
		return
	}
	buf := bufPool.Get().(*bytes.Buffer)
	defer func() {
		if buf.Cap() <= maxPoolableBufferCapacity {
			buf.Reset()
			bufPool.Put(buf)
		}
	}()
	err := errorTemplate.Execute(buf, map[string]any{
		"Referer":  r.Referer(),
		"Title":    "403 Forbidden",
		"Headline": "403 Forbidden",
		"Byline":   "Your account has been disabled.",
		"Details":  "disable reason: " + disableReason,
	})
	if err != nil {
		nbrew.GetLogger(r.Context()).Error(err.Error())
		http.Error(w, "AccountDisabled", http.StatusForbidden)
		return
	}
	w.Header().Set("Content-Security-Policy", nbrew.ContentSecurityPolicy)
	w.WriteHeader(http.StatusForbidden)
	buf.WriteTo(w)
}

// LimitedWriter is the missing counterpart of LimitedReader from the stdlib.
// https://github.com/golang/go/issues/54111#issuecomment-1220793565
type LimitedWriter struct {
	W   io.Writer // underlying writer
	N   int64     // max bytes remaining
	Err error     // error to be returned once limit is reached
}

// Write implements io.Writer.
func (lw *LimitedWriter) Write(p []byte) (int, error) {
	if lw.N < 1 {
		return 0, lw.Err
	}
	if lw.N < int64(len(p)) {
		p = p[:lw.N]
	}
	n, err := lw.W.Write(p)
	lw.N -= int64(n)
	return n, err
}

// RealClientIP returns the real client IP of the request.
func RealClientIP(r *http.Request, realIPHeaders map[netip.Addr]string, proxyIPs map[netip.Addr]struct{}) netip.Addr {
	// Reference: https://adam-p.ca/blog/2022/03/x-forwarded-for/
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}
	}
	remoteAddr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return netip.Addr{}
	}
	// If we don't have any proxy servers configured (i.e. we are directly
	// connected to the internet), treat remoteAddr as the real client IP.
	if len(realIPHeaders) == 0 && len(proxyIPs) == 0 {
		return remoteAddr
	}
	// If remoteAddr is trusted to populate a known header with the real client
	// IP, look in that header.
	if header, ok := realIPHeaders[remoteAddr]; ok {
		addr, err := netip.ParseAddr(strings.TrimSpace(r.Header.Get(header)))
		if err != nil {
			return netip.Addr{}
		}
		return addr
	}
	// Check X-Forwarded-For header only if remoteAddr is the IP of a proxy
	// server.
	_, ok := proxyIPs[remoteAddr]
	if !ok {
		return remoteAddr
	}
	// Loop over all IP addresses in X-Forwarded-For headers from right to
	// left. We want to rightmost IP address that isn't a proxy server's IP
	// address.
	values := r.Header.Values("X-Forwarded-For")
	for i := len(values) - 1; i >= 0; i-- {
		ips := strings.Split(values[i], ",")
		for j := len(ips) - 1; j >= 0; j-- {
			ip := ips[j]
			addr, err := netip.ParseAddr(strings.TrimSpace(ip))
			if err != nil {
				continue
			}
			_, ok := proxyIPs[addr]
			if ok {
				continue
			}
			return addr
		}
	}
	return netip.Addr{}
}

// MaxMindDBRecord is the struct used to retrieve the country for an IP
// address.
type MaxMindDBRecord struct {
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
}

var (
	//go:embed embed static
	embedFS embed.FS

	// RuntimeFS is the FS containing the runtime files needed by notebrew for
	// operation.
	RuntimeFS fs.FS = embedFS

	// developerMode indicates if the developer mode is enabled for the current
	// binary.
	developerMode = false

	// StylesCSS is the contents of the styles.css file in the embed/
	// directory.
	StylesCSS string

	// StylesCSSHash is the sha256 hash of the StylesCSS contents.
	StylesCSSHash string

	// BaselineJS is the contents of the baseline.js file in the embed/
	// directory.
	BaselineJS string

	// BaselineJSHash is the sha256 hash of the BaselineJS contents.
	BaselineJSHash string

	// Version holds the current notebrew git revision.
	Version string

	// commonPasswords is a set of the top 10,000 most common passwords from
	// top_10000_passwords.txt in the embed/ directory.
	commonPasswords = make(map[string]struct{})

	// CountryCodes is the ISO code to country mapping from country_codes.json
	// in the embed/ directory.
	CountryCodes map[string]string

	// ReservedSubdomains is the list of reserved subdomains that users will
	// not be able to use on the content domain.
	ReservedSubdomains = []string{"www", "cdn", "storage", "videocdn", "videostorage"}
)

func init() {
	// vcs.revision
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, setting := range info.Settings {
			if setting.Key == "vcs.revision" {
				Version = setting.Value
				break
			}
		}
	}
	// styles.css
	b, err := fs.ReadFile(embedFS, "static/styles.css")
	if err != nil {
		panic(err)
	}
	b = bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n"))
	hash := sha256.Sum256(b)
	StylesCSS = string(b)
	StylesCSSHash = "'sha256-" + base64.StdEncoding.EncodeToString(hash[:]) + "'"
	// baseline.js
	b, err = fs.ReadFile(embedFS, "static/baseline.js")
	if err != nil {
		panic(err)
	}
	b = bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n"))
	hash = sha256.Sum256(b)
	BaselineJS = string(b)
	BaselineJSHash = "'sha256-" + base64.StdEncoding.EncodeToString(hash[:]) + "'"
	// common passwords
	file, err := RuntimeFS.Open("embed/top_10000_passwords.txt")
	if err != nil {
		panic(err)
	}
	defer file.Close()
	reader := bufio.NewReader(file)
	done := false
	for {
		if done {
			break
		}
		line, err := reader.ReadBytes('\n')
		done = err == io.EOF
		if err != nil && !done {
			panic(err)
		}
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		commonPasswords[string(line)] = struct{}{}
	}
	// country codes
	file, err = RuntimeFS.Open("embed/country_codes.json")
	if err != nil {
		panic(err)
	}
	defer file.Close()
	err = json.NewDecoder(file).Decode(&CountryCodes)
	if err != nil {
		panic(err)
	}
}
