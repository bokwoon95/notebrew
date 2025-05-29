package cli

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/bokwoon95/notebrew"
	"github.com/bokwoon95/notebrew/sq"
	"github.com/bokwoon95/notebrew/stacktrace"
	"github.com/bokwoon95/sqddl/ddl"
	"github.com/caddyserver/certmagic"
	"github.com/go-sql-driver/mysql"
	"github.com/jackc/pgconn"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/klauspost/cpuid/v2"
	"github.com/libdns/cloudflare"
	"github.com/libdns/godaddy"
	"github.com/libdns/namecheap"
	"github.com/libdns/porkbun"
	"github.com/oschwald/maxminddb-golang"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
	"golang.org/x/sync/errgroup"
)

func Notebrew(configDir, dataDir string, csp map[string]string) (*notebrew.Notebrew, []io.Closer, error) {
	var closers []io.Closer
	nbrew := notebrew.New()
	logHandler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		AddSource: true,
	})
	nbrew.Logger = slog.New(logHandler).With(slog.String("version", notebrew.Version))

	// CMS domain.
	b, err := os.ReadFile(filepath.Join(configDir, "cmsdomain.txt"))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, closers, fmt.Errorf("%s: %w", filepath.Join(configDir, "cmsdomain.txt"), err)
	}
	nbrew.CMSDomain = string(bytes.TrimSpace(b))

	// Content domain.
	b, err = os.ReadFile(filepath.Join(configDir, "contentdomain.txt"))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, closers, fmt.Errorf("%s: %w", filepath.Join(configDir, "contentdomain.txt"), err)
	}
	nbrew.ContentDomain = string(bytes.TrimSpace(b))

	// Img domain.
	b, err = os.ReadFile(filepath.Join(configDir, "cdndomain.txt"))
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return nil, closers, fmt.Errorf("%s: %w", filepath.Join(configDir, "cdndomain.txt"), err)
		}
	} else {
		nbrew.CDNDomain = string(bytes.TrimSpace(b))
	}

	// Lossy img cmd.
	b, err = os.ReadFile(filepath.Join(configDir, "lossyimgcmd.txt"))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, closers, fmt.Errorf("%s: %w", filepath.Join(configDir, "lossyimgcmd.txt"), err)
	}
	nbrew.LossyImgCmd = string(bytes.TrimSpace(b))

	// Video cmd.
	b, err = os.ReadFile(filepath.Join(configDir, "videocmd.txt"))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, closers, fmt.Errorf("%s: %w", filepath.Join(configDir, "videocmd.txt"), err)
	}
	nbrew.VideoCmd = string(bytes.TrimSpace(b))

	// MaxMind DB reader.
	b, err = os.ReadFile(filepath.Join(configDir, "maxminddb.txt"))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, closers, fmt.Errorf("%s: %w", filepath.Join(configDir, "maxminddb.txt"), err)
	}
	maxMindDBFilePath := string(bytes.TrimSpace(b))
	if maxMindDBFilePath != "" {
		_, err = os.Stat(maxMindDBFilePath)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil, closers, fmt.Errorf("%s: %s does not exist", filepath.Join(configDir, "maxminddb.txt"), maxMindDBFilePath)
			}
			return nil, closers, fmt.Errorf("%s: %s: %w", filepath.Join(configDir, "maxminddb.txt"), maxMindDBFilePath, err)
		}
		maxmindDBReader, err := maxminddb.Open(maxMindDBFilePath)
		if err != nil {
			return nil, closers, fmt.Errorf("%s: %s: %w", filepath.Join(configDir, "maxminddb.txt"), maxMindDBFilePath, err)
		}
		nbrew.MaxMindDBReader = maxmindDBReader
		closers = append(closers, maxmindDBReader)
	}

	// Port.
	b, err = os.ReadFile(filepath.Join(configDir, "port.txt"))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, closers, fmt.Errorf("%s: %w", filepath.Join(configDir, "port.txt"), err)
	}
	port := string(bytes.TrimSpace(b))

	// Fill in the port and CMS domain if missing.
	if port != "" {
		nbrew.Port, err = strconv.Atoi(port)
		if err != nil {
			return nil, closers, fmt.Errorf("%s: %q is not a valid integer", filepath.Join(configDir, "port.txt"), port)
		}
		if nbrew.Port <= 0 {
			return nil, closers, fmt.Errorf("%s: %d is not a valid port", filepath.Join(configDir, "port.txt"), nbrew.Port)
		}
		if nbrew.CMSDomain == "" {
			switch nbrew.Port {
			case 443:
				return nil, closers, fmt.Errorf("%s: cannot use port 443 without specifying the cmsdomain", filepath.Join(configDir, "port.txt"))
			case 80:
				break // Use IP address as domain when we find it later.
			default:
				nbrew.CMSDomain = "localhost:" + port
			}
		}
	} else {
		if nbrew.CMSDomain != "" {
			nbrew.Port = 443
		} else {
			nbrew.Port = 6444
			nbrew.CMSDomain = "localhost:6444"
		}
	}

	if nbrew.Port == 443 || nbrew.Port == 80 {
		// IP4 and IP6.
		client := &http.Client{
			Timeout: 10 * time.Second,
		}
		group, groupctx := errgroup.WithContext(context.Background())
		group.Go(func() error {
			request, err := http.NewRequest("GET", "https://ipv4.icanhazip.com", nil)
			if err != nil {
				return fmt.Errorf("ipv4.icanhazip.com: %w", err)
			}
			response, err := client.Do(request.WithContext(groupctx))
			if err != nil {
				return fmt.Errorf("ipv4.icanhazip.com: %w", err)
			}
			defer response.Body.Close()
			var b strings.Builder
			_, err = io.Copy(&b, response.Body)
			if err != nil {
				return fmt.Errorf("ipv4.icanhazip.com: %w", err)
			}
			err = response.Body.Close()
			if err != nil {
				return err
			}
			s := strings.TrimSpace(b.String())
			if s == "" {
				return nil
			}
			ip, err := netip.ParseAddr(s)
			if err != nil {
				return fmt.Errorf("ipv4.icanhazip.com: did not get a valid IP address (%s)", s)
			}
			if ip.Is4() {
				nbrew.IP4 = ip
			}
			return nil
		})
		group.Go(func() error {
			request, err := http.NewRequest("GET", "https://ipv6.icanhazip.com", nil)
			if err != nil {
				return fmt.Errorf("ipv6.icanhazip.com: %w", err)
			}
			response, err := client.Do(request.WithContext(groupctx))
			if err != nil {
				return fmt.Errorf("ipv6.icanhazip.com: %w", err)
			}
			defer response.Body.Close()
			var b strings.Builder
			_, err = io.Copy(&b, response.Body)
			if err != nil {
				return fmt.Errorf("ipv6.icanhazip.com: %w", err)
			}
			err = response.Body.Close()
			if err != nil {
				return err
			}
			s := strings.TrimSpace(b.String())
			if s == "" {
				return nil
			}
			ip, err := netip.ParseAddr(s)
			if err != nil {
				return fmt.Errorf("ipv6.icanhazip.com: did not get a valid IP address (%s)", s)
			}
			if ip.Is6() {
				nbrew.IP6 = ip
			}
			return nil
		})
		err := group.Wait()
		if err != nil {
			return nil, closers, err
		}
		if !nbrew.IP4.IsValid() && !nbrew.IP6.IsValid() {
			return nil, closers, fmt.Errorf("unable to determine the IP address of the current machine")
		}
		if nbrew.CMSDomain == "" {
			if nbrew.IP4.IsValid() {
				nbrew.CMSDomain = nbrew.IP4.String()
			} else {
				nbrew.CMSDomain = "[" + nbrew.IP6.String() + "]"
			}
		}
	}
	if nbrew.ContentDomain == "" {
		nbrew.ContentDomain = nbrew.CMSDomain
	}

	// DNS.
	b, err = os.ReadFile(filepath.Join(configDir, "dns.json"))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, closers, fmt.Errorf("%s: %w", filepath.Join(configDir, "dns.json"), err)
	}
	b = bytes.TrimSpace(b)
	var dnsConfig DNSConfig
	if len(b) > 0 {
		decoder := json.NewDecoder(bytes.NewReader(b))
		decoder.DisallowUnknownFields()
		err := decoder.Decode(&dnsConfig)
		if err != nil {
			return nil, closers, fmt.Errorf("%s: %w", filepath.Join(configDir, "dns.json"), err)
		}
	}
	switch dnsConfig.Provider {
	case "":
		break
	case "namecheap":
		if dnsConfig.Username == "" {
			return nil, closers, fmt.Errorf("%s: namecheap: missing username field", filepath.Join(configDir, "dns.json"))
		}
		if dnsConfig.APIKey == "" {
			return nil, closers, fmt.Errorf("%s: namecheap: missing apiKey field", filepath.Join(configDir, "dns.json"))
		}
		if !nbrew.IP4.IsValid() && (nbrew.Port == 443 || nbrew.Port == 80) {
			return nil, closers, fmt.Errorf("the current machine's IP address (%s) is not IPv4: an IPv4 address is needed to integrate with namecheap's API", nbrew.IP6.String())
		}
		nbrew.DNSProvider = &namecheap.Provider{
			APIKey:      dnsConfig.APIKey,
			User:        dnsConfig.Username,
			APIEndpoint: "https://api.namecheap.com/xml.response",
			ClientIP:    nbrew.IP4.String(),
		}
	case "cloudflare":
		if dnsConfig.APIToken == "" {
			return nil, closers, fmt.Errorf("%s: cloudflare: missing apiToken field", filepath.Join(configDir, "dns.json"))
		}
		nbrew.DNSProvider = &cloudflare.Provider{
			APIToken: dnsConfig.APIToken,
		}
	case "porkbun":
		if dnsConfig.APIKey == "" {
			return nil, closers, fmt.Errorf("%s: porkbun: missing apiKey field", filepath.Join(configDir, "dns.json"))
		}
		if dnsConfig.SecretKey == "" {
			return nil, closers, fmt.Errorf("%s: porkbun: missing secretKey field", filepath.Join(configDir, "dns.json"))
		}
		nbrew.DNSProvider = &porkbun.Provider{
			APIKey:       dnsConfig.APIKey,
			APISecretKey: dnsConfig.SecretKey,
		}
	case "godaddy":
		if dnsConfig.APIToken == "" {
			return nil, closers, fmt.Errorf("%s: godaddy: missing apiToken field", filepath.Join(configDir, "dns.json"))
		}
		nbrew.DNSProvider = &godaddy.Provider{
			APIToken: dnsConfig.APIToken,
		}
	default:
		return nil, closers, fmt.Errorf("%s: unsupported provider %q (possible values: namecheap, cloudflare, porkbun, godaddy)", filepath.Join(configDir, "dns.json"), dnsConfig.Provider)
	}

	_, err1 := netip.ParseAddr(strings.TrimSuffix(strings.TrimPrefix(nbrew.CMSDomain, "["), "]"))
	_, err2 := netip.ParseAddr(strings.TrimSuffix(strings.TrimPrefix(nbrew.ContentDomain, "["), "]"))
	cmsDomainIsIP := err1 == nil
	contentDomainIsIP := err2 == nil
	if !cmsDomainIsIP {
		nbrew.Domains = append(nbrew.Domains, nbrew.CMSDomain, "www."+nbrew.CMSDomain)
		nbrew.CMSDomainHTTPS = !strings.HasPrefix(nbrew.CMSDomain, "localhost:") && nbrew.Port != 80
	}
	if !contentDomainIsIP {
		if nbrew.ContentDomain == nbrew.CMSDomain {
			nbrew.Domains = append(nbrew.Domains, "cdn."+nbrew.ContentDomain, "storage."+nbrew.ContentDomain)
			nbrew.ContentDomainHTTPS = nbrew.CMSDomainHTTPS
		} else {
			nbrew.Domains = append(nbrew.Domains, nbrew.ContentDomain, "www."+nbrew.ContentDomain, "cdn."+nbrew.ContentDomain, "storage."+nbrew.ContentDomain)
			nbrew.ContentDomainHTTPS = !strings.HasPrefix(nbrew.ContentDomain, "localhost:")
		}
	}

	// Certmagic.
	b, err = os.ReadFile(filepath.Join(configDir, "certmagic.txt"))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, closers, fmt.Errorf("%s: %w", filepath.Join(configDir, "certmagic.txt"), err)
	}
	certmagicDir := string(bytes.TrimSpace(b))
	if certmagicDir == "" {
		certmagicDir = filepath.Join(configDir, "certmagic")
	} else {
		certmagicDir = filepath.Clean(certmagicDir)
	}
	err = os.MkdirAll(certmagicDir, 0755)
	if err != nil {
		return nil, closers, err
	}
	nbrew.CertStorage = &certmagic.FileStorage{
		Path: certmagicDir,
	}

	// Certmagic Terse Logger.
	b, err = os.ReadFile(filepath.Join(configDir, "certmagic-terse-logger.txt"))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, closers, fmt.Errorf("%s: %w", filepath.Join(configDir, "certmagic-terse-logger.txt"), err)
	}
	ok, _ := strconv.ParseBool(string(bytes.TrimSpace(b)))
	if ok {
		encoderConfig := zap.NewProductionEncoderConfig()
		encoderConfig.EncodeTime = zapcore.RFC3339TimeEncoder
		terseLogger := zap.New(zapcore.NewCore(
			zapcore.NewConsoleEncoder(encoderConfig),
			os.Stderr,
			zap.ErrorLevel,
		))
		nbrew.CertLogger = terseLogger
		certmagic.Default.Logger = terseLogger
		certmagic.DefaultACME.Logger = terseLogger
	} else {
		encoderConfig := zap.NewProductionEncoderConfig()
		encoderConfig.EncodeTime = zapcore.RFC3339TimeEncoder
		verboseLogger := zap.New(zapcore.NewCore(
			zapcore.NewConsoleEncoder(encoderConfig),
			os.Stderr,
			zap.InfoLevel,
		))
		nbrew.CertLogger = verboseLogger
		certmagic.Default.Logger = verboseLogger
		certmagic.DefaultACME.Logger = verboseLogger
	}

	if nbrew.Port == 443 || nbrew.Port == 80 {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		group, groupctx := errgroup.WithContext(ctx)
		matched := make([]bool, len(nbrew.Domains))
		for i, domain := range nbrew.Domains {
			i, domain := i, domain
			group.Go(func() error {
				_, err := netip.ParseAddr(domain)
				if err == nil {
					return nil
				}
				ips, err := net.DefaultResolver.LookupIPAddr(groupctx, domain)
				if err != nil {
					fmt.Println(err)
					return nil
				}
				for _, ip := range ips {
					ip, ok := netip.AddrFromSlice(ip.IP)
					if !ok {
						continue
					}
					if ip.Is4() && ip == nbrew.IP4 || ip.Is6() && ip == nbrew.IP6 {
						matched[i] = true
						break
					}
				}
				return nil
			})
		}
		err = group.Wait()
		if err != nil {
			return nil, closers, err
		}
		if nbrew.Port == 80 {
			for i, domain := range nbrew.Domains {
				if matched[i] {
					nbrew.ManagingDomains = append(nbrew.ManagingDomains, domain)
				}
			}
		} else if nbrew.Port == 443 {
			cmsDomainWildcard := "*." + nbrew.CMSDomain
			cmsDomainWildcardAdded := false
			contentDomainWildcard := "*." + nbrew.ContentDomain
			contentDomainWildcardAdded := false
			for i, domain := range nbrew.Domains {
				if matched[i] {
					if certmagic.MatchWildcard(domain, cmsDomainWildcard) && nbrew.DNSProvider != nil {
						if !cmsDomainWildcardAdded {
							cmsDomainWildcardAdded = true
							nbrew.ManagingDomains = append(nbrew.ManagingDomains, cmsDomainWildcard)
						}
					} else if certmagic.MatchWildcard(domain, contentDomainWildcard) && nbrew.DNSProvider != nil {
						if !contentDomainWildcardAdded {
							contentDomainWildcardAdded = true
							nbrew.ManagingDomains = append(nbrew.ManagingDomains, contentDomainWildcard)
						}
					} else {
						nbrew.ManagingDomains = append(nbrew.ManagingDomains, domain)
					}
				}
			}
		}
	}

	// Database.
	b, err = os.ReadFile(filepath.Join(configDir, "database.json"))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, closers, fmt.Errorf("%s: %w", filepath.Join(configDir, "database.json"), err)
	}
	b = bytes.TrimSpace(b)
	var databaseConfig DatabaseConfig
	if len(b) > 0 {
		decoder := json.NewDecoder(bytes.NewReader(b))
		decoder.DisallowUnknownFields()
		err := decoder.Decode(&databaseConfig)
		if err != nil {
			return nil, closers, fmt.Errorf("%s: %w", filepath.Join(configDir, "database.json"), err)
		}
	}
	if databaseConfig.Dialect != "" {
		var dataSourceName string
		switch databaseConfig.Dialect {
		case "", "sqlite":
			if databaseConfig.FilePath == "" {
				databaseConfig.FilePath = filepath.Join(dataDir, "notebrew-database.db")
			}
			databaseConfig.FilePath, err = filepath.Abs(databaseConfig.FilePath)
			if err != nil {
				return nil, closers, fmt.Errorf("%s: sqlite: %w", filepath.Join(configDir, "database.json"), err)
			}
			dataSourceName = databaseConfig.FilePath + "?" + sqliteQueryString(databaseConfig.Params)
			nbrew.Dialect = "sqlite"
			nbrew.DB, err = sql.Open(sqliteDriverName, dataSourceName)
			if err != nil {
				return nil, closers, fmt.Errorf("%s: sqlite: open %s: %w", filepath.Join(configDir, "database.json"), dataSourceName, err)
			}
			closers = append(closers, nbrew.DB)
			nbrew.ErrorCode = sqliteErrorCode
		case "postgres":
			values := make(url.Values)
			for key, value := range databaseConfig.Params {
				switch key {
				case "sslmode":
					values.Set(key, value)
				}
			}
			if _, ok := databaseConfig.Params["sslmode"]; !ok {
				values.Set("sslmode", "disable")
			}
			if databaseConfig.Port == "" {
				databaseConfig.Port = "5432"
			}
			uri := url.URL{
				Scheme:   "postgres",
				User:     url.UserPassword(databaseConfig.User, databaseConfig.Password),
				Host:     databaseConfig.Host + ":" + databaseConfig.Port,
				Path:     databaseConfig.DBName,
				RawQuery: values.Encode(),
			}
			dataSourceName = uri.String()
			nbrew.Dialect = "postgres"
			nbrew.DB, err = sql.Open("pgx", dataSourceName)
			if err != nil {
				return nil, closers, fmt.Errorf("%s: postgres: open %s: %w", filepath.Join(configDir, "database.json"), dataSourceName, err)
			}
			closers = append(closers, nbrew.DB)
			nbrew.ErrorCode = func(err error) string {
				var pgErr *pgconn.PgError
				if errors.As(err, &pgErr) {
					return pgErr.Code
				}
				return ""
			}
		case "mysql":
			values := make(url.Values)
			for key, value := range databaseConfig.Params {
				switch key {
				case "charset", "collation", "loc", "maxAllowedPacket",
					"readTimeout", "rejectReadOnly", "serverPubKey", "timeout",
					"tls", "writeTimeout", "connectionAttributes":
					values.Set(key, value)
				}
			}
			values.Set("multiStatements", "true")
			values.Set("parseTime", "true")
			if databaseConfig.Port == "" {
				databaseConfig.Port = "3306"
			}
			config, err := mysql.ParseDSN(fmt.Sprintf("tcp(%s:%s)/%s?%s", databaseConfig.Host, databaseConfig.Port, url.PathEscape(databaseConfig.DBName), values.Encode()))
			if err != nil {
				return nil, closers, err
			}
			// Set user and passwd manually to accomodate special characters.
			// https://github.com/go-sql-driver/mysql/issues/1323
			config.User = databaseConfig.User
			config.Passwd = databaseConfig.Password
			driver, err := mysql.NewConnector(config)
			if err != nil {
				return nil, closers, err
			}
			dataSourceName = config.FormatDSN()
			nbrew.Dialect = "mysql"
			nbrew.DB = sql.OpenDB(driver)
			closers = append(closers, nbrew.DB)
			nbrew.ErrorCode = func(err error) string {
				var mysqlErr *mysql.MySQLError
				if errors.As(err, &mysqlErr) {
					return strconv.FormatUint(uint64(mysqlErr.Number), 10)
				}
				return ""
			}
		default:
			return nil, closers, fmt.Errorf("%s: unsupported dialect %q (possible values: sqlite, postgres, mysql)", filepath.Join(configDir, "database.json"), databaseConfig.Dialect)
		}
		err := nbrew.DB.Ping()
		if err != nil {
			return nil, closers, fmt.Errorf("%s: %s: ping %s: %w", filepath.Join(configDir, "database.json"), nbrew.Dialect, dataSourceName, err)
		}
		if databaseConfig.MaxOpenConns > 0 {
			nbrew.DB.SetMaxOpenConns(databaseConfig.MaxOpenConns)
		}
		if databaseConfig.MaxIdleConns > 0 {
			nbrew.DB.SetMaxIdleConns(databaseConfig.MaxIdleConns)
		}
		if databaseConfig.ConnMaxLifetime != "" {
			duration, err := time.ParseDuration(databaseConfig.ConnMaxLifetime)
			if err != nil {
				return nil, closers, fmt.Errorf("%s: connMaxLifetime: %s: %w", filepath.Join(configDir, "database.json"), databaseConfig.ConnMaxLifetime, err)
			}
			nbrew.DB.SetConnMaxLifetime(duration)
		}
		if databaseConfig.ConnMaxIdleTime != "" {
			duration, err := time.ParseDuration(databaseConfig.ConnMaxIdleTime)
			if err != nil {
				return nil, closers, fmt.Errorf("%s: connMaxIdleTime: %s: %w", filepath.Join(configDir, "database.json"), databaseConfig.ConnMaxIdleTime, err)
			}
			nbrew.DB.SetConnMaxIdleTime(duration)
		}
		databaseCatalog, err := notebrew.DatabaseCatalog(nbrew.Dialect)
		if err != nil {
			return nil, closers, err
		}
		automigrateCmd := &ddl.AutomigrateCmd{
			DB:             nbrew.DB,
			Dialect:        nbrew.Dialect,
			DestCatalog:    databaseCatalog,
			AcceptWarnings: true,
			Stderr:         io.Discard,
		}
		err = automigrateCmd.Run()
		if err != nil {
			return nil, closers, err
		}
		_, err = sq.Exec(context.Background(), nbrew.DB, sq.Query{
			Dialect: nbrew.Dialect,
			Format:  "INSERT INTO site (site_id, site_name) VALUES ({siteID}, '')",
			Values: []any{
				sq.UUIDParam("siteID", notebrew.NewID()),
			},
		})
		if err != nil {
			errorCode := nbrew.ErrorCode(err)
			if !notebrew.IsKeyViolation(nbrew.Dialect, errorCode) {
				return nil, closers, err
			}
		}
	}

	// Files.
	b, err = os.ReadFile(filepath.Join(configDir, "files.json"))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, closers, fmt.Errorf("%s: %w", filepath.Join(configDir, "files.json"), err)
	}
	b = bytes.TrimSpace(b)
	var filesConfig FilesConfig
	if len(b) > 0 {
		decoder := json.NewDecoder(bytes.NewReader(b))
		decoder.DisallowUnknownFields()
		err = decoder.Decode(&filesConfig)
		if err != nil {
			return nil, closers, fmt.Errorf("%s: %w", filepath.Join(configDir, "files.json"), err)
		}
	}
	if len(filesConfig.Followers) > 9 {
		filesConfig.Followers = filesConfig.Followers[:9]
	}
	fsConfigs := make([]FSConfig, 0, len(filesConfig.Followers)+1)
	fsConfigs = append(fsConfigs, FSConfig{
		Provider:             filesConfig.Provider,
		AuthenticationMethod: filesConfig.AuthenticationMethod,
		TempDir:              filesConfig.TempDir,
		Dialect:              filesConfig.Dialect,
		FilePath:             filesConfig.FilePath,
		User:                 filesConfig.User,
		Password:             filesConfig.Password,
		Host:                 filesConfig.Host,
		Port:                 filesConfig.Port,
		DBName:               filesConfig.DBName,
		Params:               filesConfig.Params,
		MaxOpenConns:         filesConfig.MaxOpenConns,
		MaxIdleConns:         filesConfig.MaxIdleConns,
		ConnMaxLifetime:      filesConfig.ConnMaxLifetime,
		ConnMaxIdleTime:      filesConfig.ConnMaxIdleTime,
	})
	for _, fsConfig := range filesConfig.Followers {
		if fsConfig.Provider == "" {
			continue
		}
		fsConfigs = append(fsConfigs, fsConfig)
	}
	var filesystems []notebrew.FS
	for _, fsConfig := range fsConfigs {
		switch fsConfig.Provider {
		case "", "directory":
			if fsConfig.FilePath == "" {
				fsConfig.FilePath = filepath.Join(dataDir, "notebrew-files")
			} else {
				fsConfig.FilePath = filepath.Clean(fsConfig.FilePath)
			}
			err := os.MkdirAll(fsConfig.FilePath, 0755)
			if err != nil {
				return nil, closers, err
			}
			dirFS, err := notebrew.NewDirectoryFS(notebrew.DirectoryFSConfig{
				RootDir: fsConfig.FilePath,
				TempDir: fsConfig.TempDir,
			})
			if err != nil {
				return nil, closers, err
			}
			filesystems = append(filesystems, dirFS)
		case "database":
			var dataSourceName string
			var dialect string
			var db *sql.DB
			var errorCode func(error) string
			switch fsConfig.Dialect {
			case "", "sqlite":
				if fsConfig.FilePath == "" {
					fsConfig.FilePath = filepath.Join(dataDir, "notebrew-files.db")
				}
				fsConfig.FilePath, err = filepath.Abs(fsConfig.FilePath)
				if err != nil {
					return nil, closers, fmt.Errorf("%s: sqlite: %w", filepath.Join(configDir, "files.json"), err)
				}
				dataSourceName = fsConfig.FilePath + "?" + sqliteQueryString(fsConfig.Params)
				dialect = "sqlite"
				db, err = sql.Open(sqliteDriverName, dataSourceName)
				if err != nil {
					return nil, closers, fmt.Errorf("%s: sqlite: open %s: %w", filepath.Join(configDir, "files.json"), dataSourceName, err)
				}
				closers = append(closers, db)
				errorCode = sqliteErrorCode
			case "postgres":
				values := make(url.Values)
				for key, value := range fsConfig.Params {
					switch key {
					case "sslmode":
						values.Set(key, value)
					}
				}
				if _, ok := fsConfig.Params["sslmode"]; !ok {
					values.Set("sslmode", "disable")
				}
				if fsConfig.Port == "" {
					fsConfig.Port = "5432"
				}
				uri := url.URL{
					Scheme:   "postgres",
					User:     url.UserPassword(fsConfig.User, fsConfig.Password),
					Host:     fsConfig.Host + ":" + fsConfig.Port,
					Path:     fsConfig.DBName,
					RawQuery: values.Encode(),
				}
				dataSourceName = uri.String()
				dialect = "postgres"
				db, err = sql.Open("pgx", dataSourceName)
				if err != nil {
					return nil, closers, fmt.Errorf("%s: postgres: open %s: %w", filepath.Join(configDir, "files.json"), dataSourceName, err)
				}
				closers = append(closers, db)
				errorCode = func(err error) string {
					var pgErr *pgconn.PgError
					if errors.As(err, &pgErr) {
						return pgErr.Code
					}
					return ""
				}
			case "mysql":
				values := make(url.Values)
				for key, value := range fsConfig.Params {
					switch key {
					case "charset", "collation", "loc", "maxAllowedPacket",
						"readTimeout", "rejectReadOnly", "serverPubKey", "timeout",
						"tls", "writeTimeout", "connectionAttributes":
						values.Set(key, value)
					}
				}
				values.Set("multiStatements", "true")
				values.Set("parseTime", "true")
				if fsConfig.Port == "" {
					fsConfig.Port = "3306"
				}
				config, err := mysql.ParseDSN(fmt.Sprintf("tcp(%s:%s)/%s?%s", fsConfig.Host, fsConfig.Port, url.PathEscape(fsConfig.DBName), values.Encode()))
				if err != nil {
					return nil, closers, err
				}
				// Set user and passwd manually to accomodate special characters.
				// https://github.com/go-sql-driver/mysql/issues/1323
				config.User = fsConfig.User
				config.Passwd = fsConfig.Password
				driver, err := mysql.NewConnector(config)
				if err != nil {
					return nil, closers, err
				}
				dataSourceName = config.FormatDSN()
				dialect = "mysql"
				db = sql.OpenDB(driver)
				closers = append(closers, db)
				errorCode = func(err error) string {
					var mysqlErr *mysql.MySQLError
					if errors.As(err, &mysqlErr) {
						return strconv.FormatUint(uint64(mysqlErr.Number), 10)
					}
					return ""
				}
			default:
				return nil, closers, fmt.Errorf("%s: unsupported dialect %q (possible values: sqlite, postgres, mysql)", filepath.Join(configDir, "files.json"), fsConfig.Dialect)
			}
			err = db.Ping()
			if err != nil {
				return nil, closers, fmt.Errorf("%s: %s: ping %s: %w", filepath.Join(configDir, "files.json"), dialect, dataSourceName, err)
			}
			if fsConfig.MaxOpenConns > 0 {
				db.SetMaxOpenConns(fsConfig.MaxOpenConns)
			}
			if fsConfig.MaxIdleConns > 0 {
				db.SetMaxIdleConns(fsConfig.MaxIdleConns)
			}
			if fsConfig.ConnMaxLifetime != "" {
				duration, err := time.ParseDuration(fsConfig.ConnMaxLifetime)
				if err != nil {
					return nil, closers, fmt.Errorf("%s: connMaxLifetime: %s: %w", filepath.Join(configDir, "files.json"), fsConfig.ConnMaxLifetime, err)
				}
				db.SetConnMaxLifetime(duration)
			}
			if fsConfig.ConnMaxIdleTime != "" {
				duration, err := time.ParseDuration(fsConfig.ConnMaxIdleTime)
				if err != nil {
					return nil, closers, fmt.Errorf("%s: connMaxIdleTime: %s: %w", filepath.Join(configDir, "files.json"), fsConfig.ConnMaxIdleTime, err)
				}
				db.SetConnMaxIdleTime(duration)
			}
			filesCatalog, err := notebrew.FilesCatalog(dialect)
			if err != nil {
				return nil, closers, err
			}
			automigrateCmd := &ddl.AutomigrateCmd{
				DB:             db,
				Dialect:        dialect,
				DestCatalog:    filesCatalog,
				AcceptWarnings: true,
				Stderr:         io.Discard,
			}
			err = automigrateCmd.Run()
			if err != nil {
				return nil, closers, err
			}
			if dialect == "sqlite" {
				dbi := ddl.NewDatabaseIntrospector(dialect, db)
				dbi.Tables = []string{"files_fts5"}
				tables, err := dbi.GetTables()
				if err != nil {
					return nil, closers, err
				}
				if len(tables) == 0 {
					_, err := db.Exec("CREATE VIRTUAL TABLE files_fts5 USING fts5 (file_name, text, content = 'files');")
					if err != nil {
						return nil, closers, err
					}
				}
				dbi.Tables = []string{"files"}
				triggers, err := dbi.GetTriggers()
				if err != nil {
					return nil, closers, err
				}
				triggerNames := make(map[string]struct{})
				for _, trigger := range triggers {
					triggerNames[trigger.TriggerName] = struct{}{}
				}
				if _, ok := triggerNames["files_after_insert"]; !ok {
					_, err := db.Exec("CREATE TRIGGER files_after_insert AFTER INSERT ON files BEGIN" +
						"\n    INSERT INTO files_fts5 (rowid, file_name, text) VALUES (NEW.rowid, NEW.file_name, NEW.text);" +
						"\nEND;",
					)
					if err != nil {
						return nil, closers, err
					}
				}
				if _, ok := triggerNames["files_after_delete"]; !ok {
					_, err := db.Exec("CREATE TRIGGER files_after_delete AFTER DELETE ON files BEGIN" +
						"\n    INSERT INTO files_fts5 (files_fts5, rowid, file_name, text) VALUES ('delete', OLD.rowid, OLD.file_name, OLD.text);" +
						"\nEND;",
					)
					if err != nil {
						return nil, closers, err
					}
				}
				if _, ok := triggerNames["files_after_update"]; !ok {
					_, err := db.Exec("CREATE TRIGGER files_after_update AFTER UPDATE ON files BEGIN" +
						"\n    INSERT INTO files_fts5 (files_fts5, rowid, file_name, text) VALUES ('delete', OLD.rowid, OLD.file_name, OLD.text);" +
						"\n    INSERT INTO files_fts5 (rowid, file_name, text) VALUES (NEW.rowid, NEW.file_name, NEW.text);" +
						"\nEND;",
					)
					if err != nil {
						return nil, closers, err
					}
				}
			}

			// Objects.
			var objectStorage notebrew.ObjectStorage
			b, err = os.ReadFile(filepath.Join(configDir, "objects.json"))
			if err != nil && !errors.Is(err, fs.ErrNotExist) {
				return nil, closers, fmt.Errorf("%s: %w", filepath.Join(configDir, "objects.json"), err)
			}
			b = bytes.TrimSpace(b)
			var objectsConfig ObjectsConfig
			if len(b) > 0 {
				decoder := json.NewDecoder(bytes.NewReader(b))
				decoder.DisallowUnknownFields()
				err = decoder.Decode(&objectsConfig)
				if err != nil {
					return nil, closers, fmt.Errorf("%s: %w", filepath.Join(configDir, "objects.json"), err)
				}
			}
			switch objectsConfig.Provider {
			case "", "directory":
				if objectsConfig.FilePath == "" {
					objectsConfig.FilePath = filepath.Join(dataDir, "notebrew-objects")
				} else {
					objectsConfig.FilePath = filepath.Clean(objectsConfig.FilePath)
				}
				err := os.MkdirAll(objectsConfig.FilePath, 0755)
				if err != nil {
					return nil, closers, err
				}
				objectStorage, err = notebrew.NewDirObjectStorage(objectsConfig.FilePath, os.TempDir())
				if err != nil {
					return nil, closers, err
				}
			case "s3":
				if objectsConfig.Endpoint == "" {
					return nil, closers, fmt.Errorf("%s: missing endpoint field", filepath.Join(configDir, "objects.json"))
				}
				if objectsConfig.Region == "" {
					return nil, closers, fmt.Errorf("%s: missing region field", filepath.Join(configDir, "objects.json"))
				}
				if objectsConfig.Bucket == "" {
					return nil, closers, fmt.Errorf("%s: missing bucket field", filepath.Join(configDir, "objects.json"))
				}
				if objectsConfig.AccessKeyID == "" {
					return nil, closers, fmt.Errorf("%s: missing accessKeyID field", filepath.Join(configDir, "objects.json"))
				}
				if objectsConfig.SecretAccessKey == "" {
					return nil, closers, fmt.Errorf("%s: missing secretAccessKey field", filepath.Join(configDir, "objects.json"))
				}
				contentTypeMap := make(map[string]string)
				for _, fileType := range notebrew.AllowedFileTypes {
					contentTypeMap[fileType.Ext] = fileType.ContentType
				}
				objectStorage, err = notebrew.NewS3Storage(context.Background(), notebrew.S3StorageConfig{
					Endpoint:        objectsConfig.Endpoint,
					Region:          objectsConfig.Region,
					Bucket:          objectsConfig.Bucket,
					AccessKeyID:     objectsConfig.AccessKeyID,
					SecretAccessKey: objectsConfig.SecretAccessKey,
					ContentTypeMap:  contentTypeMap,
					Logger:          nbrew.Logger,
				})
				if err != nil {
					return nil, closers, err
				}
			default:
				return nil, closers, fmt.Errorf("%s: unsupported provider %q (possible values: directory, s3)", filepath.Join(configDir, "objects.json"), objectsConfig.Provider)
			}
			databaseFS, err := notebrew.NewDatabaseFS(notebrew.DatabaseFSConfig{
				DB:            db,
				Dialect:       dialect,
				ErrorCode:     errorCode,
				ObjectStorage: objectStorage,
				Logger:        nbrew.Logger,
			})
			if err != nil {
				return nil, closers, err
			}
			if nbrew.DB != nil {
				databaseFS.UpdateStorageUsed = func(ctx context.Context, siteName string, delta int64) error {
					if delta == 0 {
						return nil
					}
					_, err = sq.Exec(ctx, nbrew.DB, sq.Query{
						Dialect: nbrew.Dialect,
						Format: "UPDATE site" +
							" SET storage_used = CASE WHEN coalesce(storage_used, 0) + {delta} >= 0 THEN coalesce(storage_used, 0) + {delta} ELSE 0 END" +
							" WHERE site_name = {siteName}",
						Values: []any{
							sq.Int64Param("delta", delta),
							sq.StringParam("siteName", siteName),
						},
					})
					if err != nil {
						return err
					}
					return nil
				}
			}
			filesystems = append(filesystems, databaseFS)
		case "sftp":
			if fsConfig.FilePath == "" {
				fsConfig.FilePath = "/notebrew-files"
			} else {
				if !strings.HasPrefix(fsConfig.FilePath, "/") {
					return nil, closers, fmt.Errorf("%s: filePath %q is not an absolute path", filepath.Join(configDir, "files.json"), fsConfig.FilePath)
				}
			}
			if fsConfig.TempDir == "" {
				fsConfig.TempDir = "/tmp"
			} else {
				if !strings.HasPrefix(fsConfig.TempDir, "/") {
					return nil, closers, fmt.Errorf("%s: tempDir %q is not an absolute path", filepath.Join(configDir, "files.json"), fsConfig.TempDir)
				}
			}
			homeDir, err := os.UserHomeDir()
			if err != nil {
				return nil, closers, err
			}
			hostKeyCallback, err := knownhosts.New(filepath.Join(homeDir, ".ssh", "known_hosts"))
			if err != nil {
				return nil, closers, err
			}
			sshClientConfig := &ssh.ClientConfig{
				User:            fsConfig.User,
				HostKeyCallback: hostKeyCallback,
			}
			switch fsConfig.AuthenticationMethod {
			case "", "password":
				sshClientConfig.Auth = []ssh.AuthMethod{
					ssh.Password(fsConfig.Password),
				}
			case "publickey":
				var privateKeyFileExists bool
				_, err = os.Stat(filepath.Join(homeDir, ".ssh", "id_rsa"))
				if err != nil {
					if !errors.Is(err, fs.ErrNotExist) {
						return nil, closers, err
					}
				} else {
					privateKeyFileExists = true
				}
				var publicKeyFileExists bool
				_, err = os.Stat(filepath.Join(homeDir, ".ssh", "id_rsa.pub"))
				if err != nil {
					if !errors.Is(err, fs.ErrNotExist) {
						return nil, closers, err
					}
				} else {
					publicKeyFileExists = true
				}
				if !privateKeyFileExists && !publicKeyFileExists {
					rsaPrivateKey, err := rsa.GenerateKey(rand.Reader, 4096)
					if err != nil {
						return nil, closers, err
					}
					err = rsaPrivateKey.Validate()
					if err != nil {
						return nil, closers, err
					}
					privateKeyBytes := pem.EncodeToMemory(&pem.Block{
						Type:    "RSA PRIVATE KEY",
						Headers: nil,
						Bytes:   x509.MarshalPKCS1PrivateKey(rsaPrivateKey),
					})
					publicKey, err := ssh.NewPublicKey(rsaPrivateKey.PublicKey)
					if err != nil {
						return nil, closers, err
					}
					publicKeyBytes := ssh.MarshalAuthorizedKey(publicKey)
					err = os.WriteFile(filepath.Join(homeDir, ".ssh", "id_rsa"), privateKeyBytes, 0600)
					if err != nil {
						return nil, closers, err
					}
					err = os.WriteFile(filepath.Join(homeDir, ".ssh", "id_rsa.pub"), publicKeyBytes, 0600)
					if err != nil {
						return nil, closers, err
					}
				}
				pemBytes, err := os.ReadFile(filepath.Join(homeDir, ".ssh", "id_rsa"))
				if err != nil {
					if errors.Is(err, fs.ErrNotExist) {
						return nil, closers, fmt.Errorf("%s does not exist", filepath.Join(homeDir, ".ssh", "id_rsa"))
					}
					return nil, closers, err
				}
				signer, err := ssh.ParsePrivateKey(pemBytes)
				if err != nil {
					return nil, closers, err
				}
				sshClientConfig.Auth = []ssh.AuthMethod{
					ssh.PublicKeys(signer),
				}
			default:
				return nil, closers, fmt.Errorf("%s: invalid authenticationMethod %q", filepath.Join(configDir, "files.json"), fsConfig.AuthenticationMethod)
			}
			var port string
			if fsConfig.Port == "" {
				port = ":22"
			} else {
				port = ":" + fsConfig.Port
			}
			sftpFS, err := notebrew.NewSFTPFS(notebrew.SFTPFSConfig{
				NewSSHClient: func() (*ssh.Client, error) {
					sshClient, err := ssh.Dial("tcp", fsConfig.Host+port, sshClientConfig)
					if err != nil {
						return nil, stacktrace.New(err)
					}
					return sshClient, nil
				},
				RootDir:      fsConfig.FilePath,
				TempDir:      fsConfig.TempDir,
				MaxOpenConns: fsConfig.MaxOpenConns,
			})
			if err != nil {
				return nil, closers, err
			}
			closers = append(closers, sftpFS)
			filesystems = append(filesystems, sftpFS)
		default:
			return nil, closers, fmt.Errorf("%s: unsupported provider %q (possible values: directory, database, sftp)", filepath.Join(configDir, "files.json"), fsConfig.Provider)
		}
	}
	if len(filesystems) == 1 {
		nbrew.FS = filesystems[0]
	} else {
		replicatedFS, err := notebrew.NewReplicatedFS(notebrew.ReplicatedFSConfig{
			Leader:                 filesystems[0],
			Followers:              filesystems[1:],
			SynchronousReplication: filesConfig.SynchronousReplication,
			Logger:                 nbrew.Logger,
		})
		if err != nil {
			return nil, closers, err
		}
		closers = append(closers, replicatedFS)
		nbrew.FS = replicatedFS
	}
	for _, dir := range []string{
		"notes",
		"pages",
		"posts",
		"output",
		"output/posts",
		"output/themes",
		"imports",
		"exports",
	} {
		err = nbrew.FS.Mkdir(dir, 0755)
		if err != nil && !errors.Is(err, fs.ErrExist) {
			return nil, closers, err
		}
	}
	_, err = fs.Stat(nbrew.FS, "site.json")
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return nil, closers, err
		}
		siteConfig := notebrew.SiteConfig{
			LanguageCode:   "en",
			Title:          "My Blog",
			Tagline:        "",
			Emoji:          "☕️",
			Favicon:        "",
			CodeStyle:      "onedark",
			TimezoneOffset: "+00:00",
			Description:    "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.",
			NavigationLinks: []notebrew.NavigationLink{{
				Name: "Home",
				URL:  "/",
			}, {
				Name: "Posts",
				URL:  "/posts/",
			}},
		}
		b, err := json.MarshalIndent(&siteConfig, "", "  ")
		if err != nil {
			return nil, closers, err
		}
		writer, err := nbrew.FS.OpenWriter("site.json", 0644)
		if err != nil {
			return nil, closers, err
		}
		defer writer.Close()
		_, err = io.Copy(writer, bytes.NewReader(b))
		if err != nil {
			return nil, closers, err
		}
		err = writer.Close()
		if err != nil {
			return nil, closers, err
		}
	}
	_, err = fs.Stat(nbrew.FS, "posts/postlist.json")
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return nil, closers, err
		}
		b, err := fs.ReadFile(notebrew.RuntimeFS, "embed/postlist.json")
		if err != nil {
			return nil, closers, err
		}
		writer, err := nbrew.FS.OpenWriter("posts/postlist.json", 0644)
		if err != nil {
			return nil, closers, err
		}
		defer writer.Close()
		_, err = writer.Write(b)
		if err != nil {
			return nil, closers, err
		}
		err = writer.Close()
		if err != nil {
			return nil, closers, err
		}
	}
	siteGen, err := notebrew.NewSiteGenerator(context.Background(), notebrew.SiteGeneratorConfig{
		FS:                 nbrew.FS,
		ContentDomain:      nbrew.ContentDomain,
		ContentDomainHTTPS: nbrew.ContentDomainHTTPS,
		CDNDomain:          nbrew.CDNDomain,
		SitePrefix:         "",
	})
	if err != nil {
		return nil, closers, err
	}
	_, err = fs.Stat(nbrew.FS, "pages/index.html")
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return nil, closers, err
		}
		b, err := fs.ReadFile(notebrew.RuntimeFS, "embed/index.html")
		if err != nil {
			return nil, closers, err
		}
		writer, err := nbrew.FS.OpenWriter("pages/index.html", 0644)
		if err != nil {
			return nil, closers, err
		}
		defer writer.Close()
		_, err = writer.Write(b)
		if err != nil {
			return nil, closers, err
		}
		err = writer.Close()
		if err != nil {
			return nil, closers, err
		}
		creationTime := time.Now()
		err = siteGen.GeneratePage(context.Background(), "pages/index.html", string(b), creationTime, creationTime)
		if err != nil {
			return nil, closers, err
		}
	}
	_, err = fs.Stat(nbrew.FS, "pages/404.html")
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return nil, closers, err
		}
		b, err := fs.ReadFile(notebrew.RuntimeFS, "embed/404.html")
		if err != nil {
			return nil, closers, err
		}
		writer, err := nbrew.FS.OpenWriter("pages/404.html", 0644)
		if err != nil {
			return nil, closers, err
		}
		defer writer.Close()
		_, err = writer.Write(b)
		if err != nil {
			return nil, closers, err
		}
		err = writer.Close()
		if err != nil {
			return nil, closers, err
		}
		creationTime := time.Now()
		err = siteGen.GeneratePage(context.Background(), "pages/404.html", string(b), creationTime, creationTime)
		if err != nil {
			return nil, closers, err
		}
	}
	_, err = fs.Stat(nbrew.FS, "posts/post.html")
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return nil, closers, err
		}
		b, err := fs.ReadFile(notebrew.RuntimeFS, "embed/post.html")
		if err != nil {
			return nil, closers, err
		}
		writer, err := nbrew.FS.OpenWriter("posts/post.html", 0644)
		if err != nil {
			return nil, closers, err
		}
		defer writer.Close()
		_, err = writer.Write(b)
		if err != nil {
			return nil, closers, err
		}
		err = writer.Close()
		if err != nil {
			return nil, closers, err
		}
	}
	_, err = fs.Stat(nbrew.FS, "posts/postlist.html")
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return nil, closers, err
		}
		b, err := fs.ReadFile(notebrew.RuntimeFS, "embed/postlist.html")
		if err != nil {
			return nil, closers, err
		}
		writer, err := nbrew.FS.OpenWriter("posts/postlist.html", 0644)
		if err != nil {
			return nil, closers, err
		}
		defer writer.Close()
		_, err = writer.Write(b)
		if err != nil {
			return nil, closers, err
		}
		err = writer.Close()
		if err != nil {
			return nil, closers, err
		}
		tmpl, err := siteGen.PostListTemplate(context.Background(), "")
		if err != nil {
			return nil, closers, err
		}
		_, err = siteGen.GeneratePostList(context.Background(), "", tmpl)
		if err != nil {
			return nil, closers, err
		}
	}

	// Captcha.
	b, err = os.ReadFile(filepath.Join(configDir, "captcha.json"))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, closers, fmt.Errorf("%s: %w", filepath.Join(configDir, "captcha.json"), err)
	}
	b = bytes.TrimSpace(b)
	if len(b) > 0 {
		var captchaConfig CaptchaConfig
		decoder := json.NewDecoder(bytes.NewReader(b))
		decoder.DisallowUnknownFields()
		err := decoder.Decode(&captchaConfig)
		if err != nil {
			return nil, closers, fmt.Errorf("%s: %w", filepath.Join(configDir, "captcha.json"), err)
		}
		nbrew.CaptchaConfig.WidgetScriptSrc = template.URL(captchaConfig.WidgetScriptSrc)
		nbrew.CaptchaConfig.WidgetClass = captchaConfig.WidgetClass
		nbrew.CaptchaConfig.VerificationURL = captchaConfig.VerificationURL
		nbrew.CaptchaConfig.ResponseTokenName = captchaConfig.ResponseTokenName
		nbrew.CaptchaConfig.SiteKey = captchaConfig.SiteKey
		nbrew.CaptchaConfig.SecretKey = captchaConfig.SecretKey
		nbrew.CaptchaConfig.CSP = captchaConfig.CSP
	}

	// SMTP.
	b, err = os.ReadFile(filepath.Join(configDir, "smtp.json"))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, closers, fmt.Errorf("%s: %w", filepath.Join(configDir, "smtp.json"), err)
	}
	b = bytes.TrimSpace(b)
	if len(b) > 0 {
		var smtpConfig SMTPConfig
		decoder := json.NewDecoder(bytes.NewReader(b))
		decoder.DisallowUnknownFields()
		err := decoder.Decode(&smtpConfig)
		if err != nil {
			return nil, closers, fmt.Errorf("%s: %w", filepath.Join(configDir, "smtp.json"), err)
		}
		if smtpConfig.Host != "" && smtpConfig.Port != "" && smtpConfig.Username != "" && smtpConfig.Password != "" {
			mailerConfig := notebrew.MailerConfig{
				Username: smtpConfig.Username,
				Password: smtpConfig.Password,
				Host:     smtpConfig.Host,
				Port:     smtpConfig.Port,
				Logger:   nbrew.Logger,
			}
			nbrew.MailFrom = smtpConfig.MailFrom
			nbrew.ReplyTo = smtpConfig.ReplyTo
			if smtpConfig.LimitInterval == "" {
				mailerConfig.LimitInterval = 3 * time.Minute
			} else {
				limitInterval, err := time.ParseDuration(smtpConfig.LimitInterval)
				if err != nil {
					return nil, closers, fmt.Errorf("%s: %w", filepath.Join(configDir, "smtp.json"), err)
				}
				mailerConfig.LimitInterval = limitInterval
			}
			if smtpConfig.LimitBurst <= 0 {
				mailerConfig.LimitBurst = 20
			} else {
				mailerConfig.LimitBurst = smtpConfig.LimitBurst
			}
			mailer, err := notebrew.NewMailer(mailerConfig)
			if err != nil {
				return nil, closers, err
			}
			closers = append(closers, mailer)
			nbrew.Mailer = mailer
		}
	}

	// Proxy.
	b, err = os.ReadFile(filepath.Join(configDir, "proxy.json"))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, closers, fmt.Errorf("%s: %w", filepath.Join(configDir, "proxy.json"), err)
	}
	b = bytes.TrimSpace(b)
	if len(b) > 0 {
		var proxyConfig ProxyConfig
		decoder := json.NewDecoder(bytes.NewReader(b))
		decoder.DisallowUnknownFields()
		err := decoder.Decode(&proxyConfig)
		if err != nil {
			return nil, closers, fmt.Errorf("%s: %w", filepath.Join(configDir, "proxy.json"), err)
		}
		nbrew.ProxyConfig.RealIPHeaders = make(map[netip.Addr]string)
		for ip, header := range proxyConfig.RealIPHeaders {
			addr, err := netip.ParseAddr(ip)
			if err != nil {
				return nil, closers, fmt.Errorf("%s: realIPHeaders: %s: %w", filepath.Join(configDir, "proxy.json"), ip, err)
			}
			nbrew.ProxyConfig.RealIPHeaders[addr] = header
		}
		nbrew.ProxyConfig.ProxyIPs = make(map[netip.Addr]struct{})
		for _, ip := range proxyConfig.ProxyIPs {
			addr, err := netip.ParseAddr(ip)
			if err != nil {
				return nil, closers, fmt.Errorf("%s: proxyIPs: %s: %w", filepath.Join(configDir, "proxy.json"), ip, err)
			}
			nbrew.ProxyConfig.ProxyIPs[addr] = struct{}{}
		}
	}

	// Errorlog.
	b, err = os.ReadFile(filepath.Join(configDir, "errorlog.json"))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, closers, fmt.Errorf("%s: %w", filepath.Join(configDir, "errorlog.json"), err)
	}
	b = bytes.TrimSpace(b)
	if len(b) > 0 {
		var errorlogConfig ErrorlogConfig
		decoder := json.NewDecoder(bytes.NewReader(b))
		decoder.DisallowUnknownFields()
		err := decoder.Decode(&errorlogConfig)
		if err != nil {
			return nil, closers, fmt.Errorf("%s: %w", filepath.Join(configDir, "errorlog.json"), err)
		}
		nbrew.ErrorlogConfig.Email = errorlogConfig.Email
	}

	// Content Security Policy.
	var buf strings.Builder
	// default-src
	buf.WriteString("default-src 'none';")
	// script-src
	buf.WriteString(" script-src 'self' 'unsafe-hashes' " + notebrew.BaselineJSHash)
	if value := csp["script-src"]; value != "" {
		buf.WriteString(" " + value)
	}
	if value := nbrew.CaptchaConfig.CSP["script-src"]; value != "" {
		buf.WriteString(" " + value)
	}
	buf.WriteString(";")
	// connect-src
	buf.WriteString(" connect-src 'self'")
	if value := csp["connect-src"]; value != "" {
		buf.WriteString(" " + value)
	}
	if value := nbrew.CaptchaConfig.CSP["connect-src"]; value != "" {
		buf.WriteString(" " + value)
	}
	buf.WriteString(";")
	// img-src
	buf.WriteString(" img-src 'self' data:")
	if value := csp["img-src"]; value != "" {
		buf.WriteString(" " + value)
	}
	if nbrew.CDNDomain != "" {
		buf.WriteString(" " + nbrew.CDNDomain)
	}
	buf.WriteString(";")
	// media-src
	buf.WriteString(" media-src 'self'")
	if value := csp["media-src"]; value != "" {
		buf.WriteString(" " + value)
	}
	if nbrew.CDNDomain != "" {
		buf.WriteString(" " + nbrew.CDNDomain)
	}
	buf.WriteString(";")
	// style-src
	buf.WriteString(" style-src 'self' 'unsafe-inline'")
	if value := csp["style-src"]; value != "" {
		buf.WriteString(" " + value)
	}
	if value := nbrew.CaptchaConfig.CSP["style-src"]; value != "" {
		buf.WriteString(" " + value)
	}
	buf.WriteString(";")
	// base-uri
	buf.WriteString(" base-uri 'self';")
	// form-action
	buf.WriteString(" form-action 'self'")
	if value := csp["form-action"]; value != "" {
		buf.WriteString(" " + value)
	}
	buf.WriteString(";")
	// manifest-src
	buf.WriteString(" manifest-src 'self';")
	// frame-src
	buf.WriteString(" frame-src 'self'")
	if value := csp["frame-src"]; value != "" {
		buf.WriteString(" " + value)
	}
	if value := nbrew.CaptchaConfig.CSP["frame-src"]; value != "" {
		buf.WriteString(" " + value)
	}
	buf.WriteString(";")
	nbrew.ContentSecurityPolicy = buf.String()
	return nbrew, closers, nil
}

func NewServer(nbrew *notebrew.Notebrew) (*http.Server, error) {
	server := &http.Server{
		ErrorLog: log.New(&LogFilter{Stderr: os.Stderr}, "", log.LstdFlags),
		Handler:  nbrew,
	}
	var onEvent func(ctx context.Context, event string, data map[string]any) error
	if nbrew.ErrorlogConfig.Email != "" && nbrew.Mailer != nil {
		onEvent = func(ctx context.Context, event string, data map[string]any) error {
			if event == "tls_get_certificate" {
				return nil
			}
			data["certmagic.event"] = event
			b, err := json.Marshal(data)
			if err != nil {
				fmt.Sprintln(err)
				return nil
			}
			fmt.Println(string(b))
			if event != "cert_failed" {
				return nil
			}
			renewal := fmt.Sprint(data["renewal"])
			identifier := fmt.Sprint(data["identifier"])
			remaining := fmt.Sprint(data["remaining"])
			issuers := fmt.Sprint(data["issuers"])
			errmsg := fmt.Sprint(data["error"])
			nbrew.BaseCtxWaitGroup.Add(1)
			go func() {
				defer func() {
					if v := recover(); v != nil {
						fmt.Println(stacktrace.New(fmt.Errorf("panic: %v", v)))
					}
				}()
				defer nbrew.BaseCtxWaitGroup.Done()
				mail := notebrew.Mail{
					MailFrom: nbrew.MailFrom,
					RcptTo:   nbrew.ErrorlogConfig.Email,
					Headers: []string{
						"Subject", "notebrew: certificate renewal for " + identifier + " failed: " + errmsg,
						"Content-Type", "text/plain; charset=utf-8",
					},
					Body: strings.NewReader("Certificate renewal failed." +
						"\r\nRenewal: " + renewal +
						"\r\nThe name on the certificate: " + identifier +
						"\r\nThe issuer(s) tried: " + issuers +
						"\r\nTime left on the certificate: " + remaining +
						"\r\nError: " + errmsg,
					),
				}
				select {
				case <-ctx.Done():
				case <-nbrew.BaseCtx.Done():
				case nbrew.Mailer.C <- mail:
				}
			}()
			return nil
		}
	}
	switch nbrew.Port {
	case 443:
		server.Addr = ":443"
		server.ReadHeaderTimeout = 5 * time.Minute
		server.WriteTimeout = 60 * time.Minute
		server.IdleTimeout = 5 * time.Minute
		staticCertConfig := certmagic.NewDefault()
		staticCertConfig.OnEvent = onEvent
		staticCertConfig.Storage = nbrew.CertStorage
		staticCertConfig.Logger = nbrew.CertLogger
		if nbrew.DNSProvider != nil {
			staticCertConfig.Issuers = []certmagic.Issuer{
				certmagic.NewACMEIssuer(staticCertConfig, certmagic.ACMEIssuer{
					CA:        certmagic.DefaultACME.CA,
					TestCA:    certmagic.DefaultACME.TestCA,
					Logger:    nbrew.CertLogger,
					HTTPProxy: certmagic.DefaultACME.HTTPProxy,
					DNS01Solver: &certmagic.DNS01Solver{
						DNSManager: certmagic.DNSManager{
							DNSProvider: nbrew.DNSProvider,
							Logger:      nbrew.CertLogger,
						},
					},
				}),
			}
		} else {
			staticCertConfig.Issuers = []certmagic.Issuer{
				certmagic.NewACMEIssuer(staticCertConfig, certmagic.ACMEIssuer{
					CA:        certmagic.DefaultACME.CA,
					TestCA:    certmagic.DefaultACME.TestCA,
					Logger:    nbrew.CertLogger,
					HTTPProxy: certmagic.DefaultACME.HTTPProxy,
				}),
			}
		}
		if len(nbrew.ManagingDomains) == 0 {
			fmt.Printf("WARNING: notebrew is listening on port 443 but no domains are pointing at this current machine's IP address (%s/%s). It means no traffic can reach this current machine. Please configure your DNS correctly.\n", nbrew.IP4.String(), nbrew.IP6.String())
		}
		err := staticCertConfig.ManageSync(context.Background(), nbrew.ManagingDomains)
		if err != nil {
			return nil, err
		}
		dynamicCertConfig := certmagic.NewDefault()
		dynamicCertConfig.OnEvent = onEvent
		dynamicCertConfig.Storage = nbrew.CertStorage
		dynamicCertConfig.Logger = nbrew.CertLogger
		dynamicCertConfig.OnDemand = &certmagic.OnDemandConfig{
			DecisionFunc: func(ctx context.Context, name string) error {
				if nbrew.DB != nil {
					var siteName string
					if certmagic.MatchWildcard(name, "*."+nbrew.ContentDomain) {
						siteName = strings.TrimSuffix(name, "."+nbrew.ContentDomain)
					} else {
						siteName = name
					}
					exists, err := sq.FetchExists(ctx, nbrew.DB, sq.Query{
						Dialect: nbrew.Dialect,
						Format:  "SELECT 1 FROM site WHERE site_name = {}",
						Values:  []any{siteName},
					})
					if err != nil {
						return err
					}
					if !exists {
						return fmt.Errorf("site does not exist")
					}
				} else {
					var sitePrefix string
					if certmagic.MatchWildcard(name, "*."+nbrew.ContentDomain) {
						sitePrefix = "@" + strings.TrimSuffix(name, "."+nbrew.ContentDomain)
					} else {
						sitePrefix = name
					}
					fileInfo, err := fs.Stat(nbrew.FS.WithContext(ctx), sitePrefix)
					if err != nil {
						return err
					}
					if !fileInfo.IsDir() {
						return fmt.Errorf("site does not exist")
					}
				}
				return nil
			},
		}
		server.TLSConfig = &tls.Config{
			NextProtos: []string{"h2", "http/1.1", "acme-tls/1"},
			GetCertificate: func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
				if clientHello.ServerName == "" {
					return nil, fmt.Errorf("server name required")
				}
				for _, domain := range nbrew.ManagingDomains {
					if certmagic.MatchWildcard(clientHello.ServerName, domain) {
						certificate, err := staticCertConfig.GetCertificate(clientHello)
						if err != nil {
							return nil, err
						}
						return certificate, nil
					}
				}
				certificate, err := dynamicCertConfig.GetCertificate(clientHello)
				if err != nil {
					return nil, err
				}
				return certificate, nil
			},
			MinVersion: tls.VersionTLS12,
			CurvePreferences: []tls.CurveID{
				tls.X25519,
				tls.CurveP256,
			},
			CipherSuites: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			},
			PreferServerCipherSuites: true,
		}
		if cpuid.CPU.Supports(cpuid.AESNI) {
			server.TLSConfig.CipherSuites = []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			}
		}
	case 80:
		server.Addr = ":80"
	default:
		if len(nbrew.ProxyConfig.RealIPHeaders) == 0 && len(nbrew.ProxyConfig.ProxyIPs) == 0 {
			server.Addr = "localhost:" + strconv.Itoa(nbrew.Port)
		} else {
			server.Addr = ":" + strconv.Itoa(nbrew.Port)
		}
	}
	return server, nil
}

type LogFilter struct {
	Stderr io.Writer
}

func (logFilter *LogFilter) Write(p []byte) (n int, err error) {
	if bytes.Contains(p, []byte("http: TLS handshake error from ")) ||
		bytes.Contains(p, []byte("http2: RECEIVED GOAWAY")) ||
		bytes.Contains(p, []byte("http2: server: error reading preface from client")) {
		return 0, nil
	}
	return logFilter.Stderr.Write(p)
}
