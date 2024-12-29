package notebrew

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"log/slog"
	"net/smtp"
	"strings"
	"time"

	"github.com/bokwoon95/notebrew/stacktrace"
	"golang.org/x/time/rate"
)

var (
	headerNameReplacer  = strings.NewReplacer(":", "", "\r\n", "")
	headerValueReplacer = strings.NewReplacer("\r\n", "")
)

// MailerConfig holds the parameters needed to construct a Mailer.
type MailerConfig struct {
	// (Required) SMTP username.
	Username string

	// (Required) SMTP password.
	Password string

	// (Required) SMTP host.
	Host string

	// (Required) SMTP port.
	Port string

	// (Required) Interval for replenishing one token back to the rate limiter bucket.
	LimitInterval time.Duration

	// (Required) Maximum tokens that can be held by the rate limiter bucket at any time.
	LimitBurst int

	// (Required) Logger is used for reporting errors that cannot be handled
	// and are thrown away.
	Logger *slog.Logger
}

// Mailer is responsible for sending emails (using SMTP). Send emails by
// writing to its C channel. Example:
//
//	mailer.C <- Mail{
//	    MailFrom: "sender@email.com",
//	    RcptTo:   "recipient@example.com",
//	    Headers: []string{
//	        "Subject", "Hello World!",
//	        "Content-Type", "text/html; charset=utf-8",
//	    },
//	    Body: strings.NewReader("<h1>Hello World!</h1>"),
//	}
//
// Once the mailer sends an email, it will keep the SMTP connection alive for
// up to 100 seconds. If another mail comes through the channel during that
// period, the SMTP connection will be reused to send that email and refreshes
// its timeout duration for another 100 seconds. When the mailer times out, the
// SMTP connection will be closed and any future mails will require
// establishing a new connection to the SMTP server.
//
// Using rate limiter is opt-in (but advised) and has to be manually invoked by
// calling mailer.Limiter.Wait(ctx) or mailer.Limiter.Allow().
type Mailer struct {
	// (Required) SMTP username.
	Username string

	// (Required) SMTP password.
	Password string

	// (Required) SMTP host.
	Host string

	// (Required) SMTP port.
	Port string

	// Limiter is a rate limiter set by the LimitInterval and LimitBurst fields
	// in MailerConfig.
	Limiter *rate.Limiter

	// C is the mail channel.
	C chan Mail

	// Logger is used for reporting errors that cannot be handled and are
	// thrown away.
	Logger *slog.Logger

	// baseCtx is the base context of the Mailer.
	baseCtx context.Context

	// baseCtxCancel cancels the base context.
	baseCtxCancel func()

	// The stopped channel is closed by the mailer background job when it
	// returns.
	stopped chan struct{}
}

// Mail represents an SMTP email to be sent.
type Mail struct {
	// MailFrom is the SMTP MAIL FROM instruction.
	MailFrom string

	// RcptTo is the SMTP RCPT TO instruction.
	RcptTo string

	// Headers are the SMTP headers, in the header name value pairs. Example:
	//
	//   []string{
	//       "Subject", "Hello World!",
	//       "Content-Type", "text/html; charset=utf-8",
	//       "Reply-To", "helpdesk@example.com",
	//   }
	Headers []string

	// Body is the SMTP email body.
	Body io.Reader
}

// NewMailer constructs a new Mailer. It starts a background job listening for
// incoming mails on the C channel, which can be shut down by calling the
// Close() method.
func NewMailer(config MailerConfig) (*Mailer, error) {
	baseCtx, baseCtxCancel := context.WithCancel(context.Background())
	mailer := &Mailer{
		Username:      config.Username,
		Password:      config.Password,
		Host:          config.Host,
		Port:          config.Port,
		Limiter:       rate.NewLimiter(rate.Every(config.LimitInterval), config.LimitBurst),
		C:             make(chan Mail, config.LimitBurst),
		Logger:        config.Logger,
		baseCtx:       baseCtx,
		baseCtxCancel: baseCtxCancel,
		stopped:       make(chan struct{}),
	}
	// Ping the SMTP server to see if the credentials are correct.
	client, err := mailer.NewClient()
	if err != nil {
		return nil, err
	}
	err = client.Quit()
	if err != nil {
		return nil, err
	}
	// Start the background job listening on the C channel.
	go mailer.start()
	return mailer, nil
}

// NewClient returns a new SMTP client.
func (mailer *Mailer) NewClient() (*smtp.Client, error) {
	var err error
	var client *smtp.Client
	if mailer.Port == "465" {
		conn, err := tls.Dial("tcp", mailer.Host+":"+mailer.Port, &tls.Config{
			ServerName: mailer.Host,
		})
		if err != nil {
			return nil, stacktrace.New(err)
		}
		client, err = smtp.NewClient(conn, mailer.Host)
		if err != nil {
			return nil, stacktrace.New(err)
		}
	} else {
		client, err = smtp.Dial(mailer.Host + ":" + mailer.Port)
		if err != nil {
			return nil, stacktrace.New(err)
		}
		if mailer.Port == "587" {
			err := client.StartTLS(&tls.Config{
				ServerName: mailer.Host,
			})
			if err != nil {
				return nil, stacktrace.New(err)
			}
		}
	}
	err = client.Auth(smtp.PlainAuth("", mailer.Username, mailer.Password, mailer.Host))
	if err != nil {
		return nil, stacktrace.New(err)
	}
	return client, nil
}

// start starts a background job listening on the C channel and
// sending emails that come through.
func (mailer *Mailer) start() {
	defer close(mailer.stopped)
	timer := time.NewTimer(0)
	<-timer.C
	defer timer.Stop()
	var buf bytes.Buffer
	for {
		select {
		case <-mailer.baseCtx.Done():
			return
		case mail := <-mailer.C:
			if mail.RcptTo == "" {
				break
			}
			client, err := mailer.NewClient()
			if err != nil {
				mailer.Logger.Error(err.Error())
				break
			}
			quit := false
			for !quit {
				err := client.Mail(mail.MailFrom)
				if err != nil {
					mailer.Logger.Error(err.Error(), slog.String("mailFrom", mail.MailFrom), slog.String("rcptTo", mail.RcptTo), slog.String("rcptTo", strings.Join(mail.Headers, "|")))
					break
				}
				err = client.Rcpt(mail.RcptTo)
				if err != nil {
					mailer.Logger.Error(err.Error(), slog.String("mailFrom", mail.MailFrom), slog.String("rcptTo", mail.RcptTo), slog.String("rcptTo", strings.Join(mail.Headers, "|")))
					break
				}
				buf.Reset()
				buf.WriteString("MIME-version: 1.0\r\n")
				buf.WriteString("From: " + headerValueReplacer.Replace(mail.MailFrom) + "\r\n")
				buf.WriteString("To: " + headerValueReplacer.Replace(mail.RcptTo) + "\r\n")
				for i := 0; i+1 < len(mail.Headers); i += 2 {
					name, value := mail.Headers[i], mail.Headers[i+1]
					buf.WriteString(headerNameReplacer.Replace(name) + ": " + headerValueReplacer.Replace(value) + "\r\n")
				}
				buf.WriteString("\r\n")
				writer, err := client.Data()
				if err != nil {
					mailer.Logger.Error(err.Error(), slog.String("mailFrom", mail.MailFrom), slog.String("rcptTo", mail.RcptTo), slog.String("rcptTo", strings.Join(mail.Headers, "|")))
					break
				}
				_, err = io.Copy(writer, &buf)
				if err != nil {
					writer.Close()
					mailer.Logger.Error(err.Error(), slog.String("mailFrom", mail.MailFrom), slog.String("rcptTo", mail.RcptTo), slog.String("rcptTo", strings.Join(mail.Headers, "|")))
					break
				}
				_, err = io.Copy(writer, mail.Body)
				if err != nil {
					writer.Close()
					mailer.Logger.Error(err.Error(), slog.String("mailFrom", mail.MailFrom), slog.String("rcptTo", mail.RcptTo), slog.String("rcptTo", strings.Join(mail.Headers, "|")))
					break
				}
				err = writer.Close()
				if err != nil {
					mailer.Logger.Error(err.Error(), slog.String("mailFrom", mail.MailFrom), slog.String("rcptTo", mail.RcptTo), slog.String("rcptTo", strings.Join(mail.Headers, "|")))
					break
				}
				timer.Reset(100 * time.Second)
				select {
				case <-mailer.baseCtx.Done():
					return
				case <-timer.C:
					quit = true
				case mail = <-mailer.C:
					timer.Stop()
					err = client.Reset()
					if err != nil {
						mailer.Logger.Error(err.Error())
						quit = true
					}
				}
			}
			err = client.Quit()
			if err != nil {
				mailer.Logger.Error(err.Error())
				break
			}
		}
	}
}

// Close shuts down the background job listening for incoming mail on the C
// channel and returns when the background job is completed.
func (mailer *Mailer) Close() error {
	mailer.baseCtxCancel()
	<-mailer.stopped
	return nil
}
