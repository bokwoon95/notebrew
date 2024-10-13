package sq

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// Dialects supported.
const (
	DialectSQLite    = "sqlite"
	DialectPostgres  = "postgres"
	DialectMySQL     = "mysql"
	DialectSQLServer = "sqlserver"
)

// SQLWriter is anything that can be converted to SQL.
type SQLWriter interface {
	// WriteSQL writes the SQL representation of the SQLWriter into the query
	// string (*bytes.Buffer) and args slice (*[]any).
	//
	// The params map is used to hold the mappings between named parameters in
	// the query to the corresponding index in the args slice and is used for
	// rebinding args by their parameter name. The params map may be nil, check
	// first before writing to it.
	WriteSQL(ctx context.Context, dialect string, buf *bytes.Buffer, args *[]any, params map[string][]int) error
}

// DB is a database/sql abstraction that can query the database. *sql.Conn,
// *sql.DB and *sql.Tx all implement DB.
type DB interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	PrepareContext(ctx context.Context, query string) (*sql.Stmt, error)
}

// DialectValuer is any type that will yield a different driver.Valuer
// depending on the SQL dialect.
type DialectValuer interface {
	DialectValuer(dialect string) (driver.Valuer, error)
}

// UUIDValue takes in a type whose underlying type must be a [16]byte and
// returns a driver.Valuer.
func UUID(value [16]byte) driver.Valuer {
	return &uuidValue{value: value}
}

type uuidValue struct {
	dialect string
	value   [16]byte
}

// Value implements the driver.Valuer interface.
func (v *uuidValue) Value() (driver.Value, error) {
	if v.value == [16]byte{} {
		return nil, nil
	}
	if v.dialect != DialectPostgres {
		return v.value[:], nil
	}
	var b [36]byte
	hex.Encode(b[:], v.value[:4])
	b[8] = '-'
	hex.Encode(b[9:13], v.value[4:6])
	b[13] = '-'
	hex.Encode(b[14:18], v.value[6:8])
	b[18] = '-'
	hex.Encode(b[19:23], v.value[8:10])
	b[23] = '-'
	hex.Encode(b[24:], v.value[10:])
	return string(b[:]), nil
}

// DialectValuer implements the DialectValuer interface.
func (v *uuidValue) DialectValuer(dialect string) (driver.Valuer, error) {
	v.dialect = dialect
	return v, nil
}

// Timestamp is as a replacement for sql.NullTime but with the following
// enhancements:
//
// 1. Timestamp.Value() returns an int64 unix timestamp if the dialect is
// SQLite, otherwise it returns a time.Time (similar to sql.NullTime).
//
// 2. Timestamp.Scan() additionally supports scanning from int64 and text
// (string/[]byte) values on top of what sql.NullTime already supports. The
// following text timestamp formats are supported:
//
//	var timestampFormats = []string{
//		"2006-01-02 15:04:05.999999999-07:00",
//		"2006-01-02T15:04:05.999999999-07:00",
//		"2006-01-02 15:04:05.999999999",
//		"2006-01-02T15:04:05.999999999",
//		"2006-01-02 15:04:05",
//		"2006-01-02T15:04:05",
//		"2006-01-02 15:04",
//		"2006-01-02T15:04",
//		"2006-01-02",
//	}
type Timestamp struct {
	time.Time
	Valid   bool
	dialect string
}

func NewTimestamp(t time.Time) *Timestamp {
	return &Timestamp{Time: t, Valid: true}
}

// copied from https://pkg.go.dev/github.com/mattn/go-sqlite3#pkg-variables
var timestampFormats = []string{
	"2006-01-02 15:04:05.999999999-07:00",
	"2006-01-02T15:04:05.999999999-07:00",
	"2006-01-02 15:04:05.999999999",
	"2006-01-02T15:04:05.999999999",
	"2006-01-02 15:04:05",
	"2006-01-02T15:04:05",
	"2006-01-02 15:04",
	"2006-01-02T15:04",
	"2006-01-02",
}

// Scan implements the sql.Scanner interface. It additionally supports scanning
// from int64 and text (string/[]byte) values on top of what sql.NullTime
// already supports. The following text timestamp formats are supported:
//
//	var timestampFormats = []string{
//		"2006-01-02 15:04:05.999999999-07:00",
//		"2006-01-02T15:04:05.999999999-07:00",
//		"2006-01-02 15:04:05.999999999",
//		"2006-01-02T15:04:05.999999999",
//		"2006-01-02 15:04:05",
//		"2006-01-02T15:04:05",
//		"2006-01-02 15:04",
//		"2006-01-02T15:04",
//		"2006-01-02",
//	}
func (ts *Timestamp) Scan(value any) error {
	if value == nil {
		ts.Time, ts.Valid = time.Time{}, false
		return nil
	}
	// int64 and string handling copied from
	// https://github.com/mattn/go-sqlite3/issues/748#issuecomment-538643131
	switch value := value.(type) {
	case int64:
		// Assume a millisecond unix timestamp if it's 13 digits -- too
		// large to be a reasonable timestamp in seconds.
		if value > 1e12 || value < -1e12 {
			value *= int64(time.Millisecond) // convert ms to nsec
			ts.Time = time.Unix(0, value).UTC()
		} else {
			ts.Time = time.Unix(value, 0).UTC()
		}
		ts.Valid = true
		return nil
	case string:
		if len(value) == 0 {
			ts.Time, ts.Valid = time.Time{}, false
			return nil
		}
		var err error
		var timeVal time.Time
		value = strings.TrimSuffix(value, "Z")
		for _, format := range timestampFormats {
			if timeVal, err = time.ParseInLocation(format, value, time.UTC); err == nil {
				ts.Time, ts.Valid = timeVal, true
				return nil
			}
		}
		return fmt.Errorf("could not convert %q into time", value)
	case []byte:
		if len(value) == 0 {
			ts.Time, ts.Valid = time.Time{}, false
			return nil
		}
		var err error
		var timeVal time.Time
		value = bytes.TrimSuffix(value, []byte("Z"))
		for _, format := range timestampFormats {
			if timeVal, err = time.ParseInLocation(format, string(value), time.UTC); err == nil {
				ts.Time, ts.Valid = timeVal, true
				return nil
			}
		}
		return fmt.Errorf("could not convert %q into time", value)
	default:
		var nulltime sql.NullTime
		err := nulltime.Scan(value)
		if err != nil {
			return err
		}
		ts.Time, ts.Valid = nulltime.Time, nulltime.Valid
		return nil
	}
}

// Value implements the driver.Valuer interface. It returns an int64 unix
// timestamp if the dialect is SQLite, otherwise it returns a time.Time
// (similar to sql.NullTime).
func (ts *Timestamp) Value() (driver.Value, error) {
	if !ts.Valid {
		return nil, nil
	}
	if ts.dialect == DialectSQLite {
		return ts.Time.UTC().Unix(), nil
	}
	return ts.Time, nil
}

// DialectValuer implements the DialectValuer interface.
func (ts *Timestamp) DialectValuer(dialect string) (driver.Valuer, error) {
	ts.dialect = dialect
	return ts, nil
}
