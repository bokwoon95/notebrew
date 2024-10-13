package sq

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/hex"
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
)

var bufPool = &sync.Pool{
	New: func() any { return &bytes.Buffer{} },
}

var ordinalIndexPool = sync.Pool{
	New: func() any { return map[int]int{} },
}

var namedIndexPool = sync.Pool{
	New: func() any { return map[string]int{} },
}

var argsPool = sync.Pool{
	New: func() any { return &[]any{} },
}

var paramsPool = sync.Pool{
	New: func() any { return map[string][]int{} },
}

// Writef is a fmt.Sprintf-style function that will write a format string and
// values slice into an Output. The only recognized placeholder is '{}'.
// Placeholders can be anonymous (e.g. {}), ordinal (e.g. {1}, {2}, {3}) or
// named (e.g. {name}, {email}, {age}).
//
// - Anonymous placeholders refer to successive values in the values slice.
// Anonymous placeholders are treated like a series of incrementing ordinal
// placeholders.
//
// - Ordinal placeholders refer to a specific value in the values slice using
// 1-based indexing.
//
// - Named placeholders refer to their corresponding sql.NamedArg value in the
// values slice. If there are multiple sql.NamedArg values with the same name,
// the last one wins.
//
// If a value is an SQLWriter, its WriteSQL method will be called. Else if a
// value is a slice, it will undergo slice expansion
// (https://bokwoon.neocities.org/sq.html#value-expansion). Otherwise, the
// value is added to the query args slice.
func Writef(ctx context.Context, dialect string, buf *bytes.Buffer, args *[]any, params map[string][]int, format string, values []any) error {
	ordinalIndex := ordinalIndexPool.Get().(map[int]int)
	clear(ordinalIndex)
	defer ordinalIndexPool.Put(ordinalIndex)
	return writef(ctx, dialect, buf, args, params, format, values, new(int), ordinalIndex)
}

// ordinalIndex tracks the index of the ordinals that have already been written
// into the args slice
func writef(ctx context.Context, dialect string, buf *bytes.Buffer, args *[]any, params map[string][]int, format string, values []any, runningValuesIndex *int, ordinalIndex map[int]int) error {
	// optimized case when the format string does not contain any '{}'
	// placeholders
	if i := strings.IndexByte(format, '{'); i < 0 {
		buf.WriteString(format)
		return nil
	}

	// namedIndex tracks the indexes of the namedArgs that are inside the
	// values slice
	namedIndex := namedIndexPool.Get().(map[string]int)
	clear(namedIndex)
	defer namedIndexPool.Put(namedIndex)
	for i, value := range values {
		var name string
		switch arg := value.(type) {
		case sql.NamedArg:
			name = arg.Name
		case Parameter:
			name = arg.Name
		}
		if name != "" {
			if _, ok := namedIndex[name]; ok {
				return fmt.Errorf("named parameter {%s} provided more than once", name)
			}
			namedIndex[name] = i
		}
	}
	buf.Grow(len(format))

	// jump to each '{' character in the format string
	for i := strings.IndexByte(format, '{'); i >= 0; i = strings.IndexByte(format, '{') {
		// Unescape '{{' to '{'
		if i+1 <= len(format) && format[i+1] == '{' {
			buf.WriteString(format[:i])
			buf.WriteByte('{')
			format = format[i+2:]
			continue
		}
		buf.WriteString(format[:i])
		format = format[i:]

		// If we can't find the terminating '}' return an error
		j := strings.IndexByte(format, '}')
		if j < 0 {
			return fmt.Errorf("no '}' found")
		}

		paramName := format[1:j]
		format = format[j+1:]
		for _, char := range paramName {
			if char != '_' && !unicode.IsLetter(char) && !unicode.IsDigit(char) {
				return fmt.Errorf("%q is not a valid param name (only letters, digits and '_' are allowed)", paramName)
			}
		}

		// is it an anonymous placeholder? e.g. {}
		if paramName == "" {
			if *runningValuesIndex >= len(values) {
				return fmt.Errorf("too few values passed in to Writef, expected more than %d", runningValuesIndex)
			}
			value := values[*runningValuesIndex]
			*runningValuesIndex++
			err := WriteValue(ctx, dialect, buf, args, params, value)
			if err != nil {
				return err
			}
			continue
		}

		// is it an ordinal placeholder? e.g. {1}, {2}, {3}
		ordinal, err := strconv.Atoi(paramName)
		if err == nil {
			err = writeOrdinalValue(ctx, dialect, buf, args, params, values, ordinal, ordinalIndex)
			if err != nil {
				return err
			}
			continue
		}

		// is it a named placeholder? e.g. {name}, {age}, {email}
		index, ok := namedIndex[paramName]
		if !ok {
			if len(namedIndex) == 0 {
				return fmt.Errorf("named parameter {%s} not provided", paramName)
			}
			availableParams := make([]string, 0, len(namedIndex))
			for name := range namedIndex {
				availableParams = append(availableParams, name)
			}
			sort.Strings(availableParams)
			return fmt.Errorf("named parameter {%s} not provided (available params: %s)", paramName, strings.Join(availableParams, ", "))
		}
		value := values[index]
		err = WriteValue(ctx, dialect, buf, args, params, value)
		if err != nil {
			return err
		}
	}
	buf.WriteString(format)
	return nil
}

func preprocessValue(dialect string, value any) (any, error) {
	if dialectValuer, ok := value.(DialectValuer); ok {
		driverValuer, err := dialectValuer.DialectValuer(dialect)
		if err != nil {
			return nil, fmt.Errorf("calling DialectValuer on %#v: %w", dialectValuer, err)
		}
		value = driverValuer
	}
	switch value := value.(type) {
	case nil:
		return nil, nil
	case [16]byte:
		driverValue, err := (&uuidValue{dialect: dialect, value: value}).Value()
		if err != nil {
			if dialect == DialectPostgres {
				return nil, fmt.Errorf("converting %#v to string: %w", value, err)
			}
			return nil, fmt.Errorf("converting %#v to bytes: %w", value, err)
		}
		return driverValue, nil
	case driver.Valuer:
		driverValue, err := value.Value()
		if err != nil {
			return nil, fmt.Errorf("calling Value on %#v: %w", value, err)
		}
		return driverValue, nil
	}
	return value, nil
}

// WriteValue is the equivalent of Writef but for writing a single value into
// the Output.
func WriteValue(ctx context.Context, dialect string, buf *bytes.Buffer, args *[]any, params map[string][]int, value any) error {
	if namedArg, ok := value.(sql.NamedArg); ok {
		return writeNamedArg(ctx, dialect, buf, args, params, namedArg)
	}
	if w, ok := value.(SQLWriter); ok {
		return w.WriteSQL(ctx, dialect, buf, args, params)
	}
	if isExpandableSlice(value) {
		return expandSlice(ctx, dialect, buf, args, params, value)
	}
	value, err := preprocessValue(dialect, value)
	if err != nil {
		return err
	}
	*args = append(*args, value)
	index := len(*args) - 1
	switch dialect {
	case DialectPostgres, DialectSQLite:
		buf.WriteString("$" + strconv.Itoa(index+1))
	case DialectSQLServer:
		buf.WriteString("@p" + strconv.Itoa(index+1))
	default:
		buf.WriteString("?")
	}
	return nil
}

// QuoteIdentifier quotes an identifier if necessary using dialect-specific
// quoting rules.
func QuoteIdentifier(dialect string, identifier string) string {
	var needsQuoting bool
	switch identifier {
	case "":
		needsQuoting = true
	case "EXCLUDED", "INSERTED", "DELETED", "NEW", "OLD":
		needsQuoting = false
	default:
		for i, char := range identifier {
			if i == 0 && (char >= '0' && char <= '9') {
				// first character cannot be a number
				needsQuoting = true
				break
			}
			if char == '_' || (char >= '0' && char <= '9') || (char >= 'a' && char <= 'z') {
				continue
			}
			// If there are capital letters, the identifier is quoted to preserve
			// capitalization information (because databases treat capital letters
			// differently based on their dialect or configuration).
			// If the character is anything else, we also quote. In general there
			// may be some special characters that are allowed in unquoted
			// identifiers (e.g. '$'), but different databases allow different
			// things. We only recognize _a-z0-9 as the true standard.
			needsQuoting = true
			break
		}
		if !needsQuoting && dialect != "" {
			switch dialect {
			case DialectSQLite:
				_, needsQuoting = sqliteKeywords[strings.ToLower(identifier)]
			case DialectPostgres:
				_, needsQuoting = postgresKeywords[strings.ToLower(identifier)]
			case DialectMySQL:
				_, needsQuoting = mysqlKeywords[strings.ToLower(identifier)]
			case DialectSQLServer:
				_, needsQuoting = sqlserverKeywords[strings.ToLower(identifier)]
			}
		}
	}
	if !needsQuoting {
		return identifier
	}
	switch dialect {
	case DialectMySQL:
		return "`" + EscapeQuote(identifier, '`') + "`"
	case DialectSQLServer:
		return "[" + EscapeQuote(identifier, ']') + "]"
	default:
		return `"` + EscapeQuote(identifier, '"') + `"`
	}
}

// EscapeQuote will escape the relevant quote in a string by doubling up on it
// (as per SQL rules).
func EscapeQuote(str string, quote byte) string {
	i := strings.IndexByte(str, quote)
	if i < 0 {
		return str
	}
	var b strings.Builder
	b.Grow(len(str) + strings.Count(str, string(quote)))
	for i >= 0 {
		b.WriteString(str[:i])
		b.WriteByte(quote)
		b.WriteByte(quote)
		if len(str[i:]) > 2 && str[i] == quote && str[i+1] == quote {
			str = str[i+2:]
		} else {
			str = str[i+1:]
		}
		i = strings.IndexByte(str, quote)
	}
	b.WriteString(str)
	return b.String()
}

// Sprintf will interpolate SQL args into a query string containing prepared
// statement parameters. It returns an error if an argument cannot be properly
// represented in SQL.
func Sprintf(dialect string, query string, args []any) (string, error) {
	if len(args) == 0 {
		return query, nil
	}
	buf := bufPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer bufPool.Put(buf)
	buf.Grow(len(query))
	namedIndices := make(map[string]int)
	for i, arg := range args {
		switch arg := arg.(type) {
		case sql.NamedArg:
			namedIndices[arg.Name] = i
		}
	}
	runningArgsIndex := 0
	mustWriteCharAt := -1
	insideStringOrIdentifier := false
	var openingQuote rune
	var paramName []rune
	for i, char := range query {
		// do we unconditionally write in the current char?
		if mustWriteCharAt == i {
			buf.WriteRune(char)
			continue
		}
		// are we currently inside a string or identifier?
		if insideStringOrIdentifier {
			buf.WriteRune(char)
			switch openingQuote {
			case '\'', '"', '`':
				// does the current char terminate the current string or identifier?
				if char == openingQuote {
					// is the next char the same as the current char, which
					// escapes it and prevents it from terminating the current
					// string or identifier?
					if i+1 < len(query) && rune(query[i+1]) == openingQuote {
						mustWriteCharAt = i + 1
					} else {
						insideStringOrIdentifier = false
					}
				}
			case '[':
				// does the current char terminate the current string or identifier?
				if char == ']' {
					// is the next char the same as the current char, which
					// escapes it and prevents it from terminating the current
					// string or identifier?
					if i+1 < len(query) && query[i+1] == ']' {
						mustWriteCharAt = i + 1
					} else {
						insideStringOrIdentifier = false
					}
				}
			}
			continue
		}
		// does the current char mark the start of a new string or identifier?
		if char == '\'' || char == '"' || (char == '`' && dialect == DialectMySQL) || (char == '[' && dialect == DialectSQLServer) {
			insideStringOrIdentifier = true
			openingQuote = char
			buf.WriteRune(char)
			continue
		}
		// are we currently inside a parameter name?
		if len(paramName) > 0 {
			// does the current char terminate the current parameter name?
			if char != '_' && !unicode.IsLetter(char) && !unicode.IsDigit(char) {
				paramValue, err := lookupParam(dialect, args, paramName, namedIndices, runningArgsIndex)
				if err != nil {
					return buf.String(), err
				}
				buf.WriteString(paramValue)
				buf.WriteRune(char)
				if len(paramName) == 1 && paramName[0] == '?' {
					runningArgsIndex++
				}
				paramName = paramName[:0]
			} else {
				paramName = append(paramName, char)
			}
			continue
		}
		// does the current char mark the start of a new parameter name?
		if (char == '$' && (dialect == DialectSQLite || dialect == DialectPostgres)) ||
			(char == ':' && dialect == DialectSQLite) ||
			(char == '@' && (dialect == DialectSQLite || dialect == DialectSQLServer)) {
			paramName = append(paramName, char)
			continue
		}
		// is the current char the anonymous '?' parameter?
		if char == '?' && dialect != DialectPostgres {
			// for sqlite, just because we encounter a '?' doesn't mean it
			// is an anonymous param. sqlite also supports using '?' for
			// ordinal params (e.g. ?1, ?2, ?3) or named params (?foo,
			// ?bar, ?baz). Hence we treat it as an ordinal/named param
			// first, and handle the edge case later when it isn't.
			if dialect == DialectSQLite {
				paramName = append(paramName, char)
				continue
			}
			if runningArgsIndex >= len(args) {
				return buf.String(), fmt.Errorf("too few args provided, expected more than %d", runningArgsIndex+1)
			}
			paramValue, err := Sprint(dialect, args[runningArgsIndex])
			if err != nil {
				return buf.String(), err
			}
			buf.WriteString(paramValue)
			runningArgsIndex++
			continue
		}
		// if all the above questions answer false, we just write the current
		// char in and continue
		buf.WriteRune(char)
	}
	// flush the paramName buffer (to handle edge case where the query ends
	// with a parameter name e.g. "SELECT * FROM tbl WHERE x = :param")
	if len(paramName) > 0 {
		paramValue, err := lookupParam(dialect, args, paramName, namedIndices, runningArgsIndex)
		if err != nil {
			return buf.String(), err
		}
		buf.WriteString(paramValue)
	}
	if insideStringOrIdentifier {
		return buf.String(), fmt.Errorf("unclosed string or identifier")
	}
	return buf.String(), nil
}

// Sprint is the equivalent of Sprintf but for converting a single value into
// its SQL representation.
func Sprint(dialect string, v any) (string, error) {
	const (
		timestamp             = "2006-01-02 15:04:05"
		timestampWithTimezone = "2006-01-02 15:04:05.9999999-07:00"
	)
	switch v := v.(type) {
	case nil:
		return "NULL", nil
	case bool:
		if v {
			if dialect == DialectSQLServer {
				return "1", nil
			}
			return "TRUE", nil
		}
		if dialect == DialectSQLServer {
			return "0", nil
		}
		return "FALSE", nil
	case []byte:
		switch dialect {
		case DialectPostgres:
			// https://www.postgresql.org/docs/current/datatype-binary.html
			// (see 8.4.1. bytea Hex Format)
			return `'\x` + hex.EncodeToString(v) + `'`, nil
		case DialectSQLServer:
			return `0x` + hex.EncodeToString(v), nil
		default:
			return `x'` + hex.EncodeToString(v) + `'`, nil
		}
	case string:
		str := v
		i := strings.IndexAny(str, "\r\n")
		if i < 0 {
			return `'` + strings.ReplaceAll(str, `'`, `''`) + `'`, nil
		}
		var b strings.Builder
		if dialect == DialectMySQL || dialect == DialectSQLServer {
			b.WriteString("CONCAT(")
		}
		for i >= 0 {
			if str[:i] != "" {
				b.WriteString(`'` + strings.ReplaceAll(str[:i], `'`, `''`) + `'`)
				if dialect == DialectMySQL || dialect == DialectSQLServer {
					b.WriteString(", ")
				} else {
					b.WriteString(" || ")
				}
			}
			switch str[i] {
			case '\r':
				if dialect == DialectPostgres {
					b.WriteString("CHR(13)")
				} else {
					b.WriteString("CHAR(13)")
				}
			case '\n':
				if dialect == DialectPostgres {
					b.WriteString("CHR(10)")
				} else {
					b.WriteString("CHAR(10)")
				}
			}
			if str[i+1:] != "" {
				if dialect == DialectMySQL || dialect == DialectSQLServer {
					b.WriteString(", ")
				} else {
					b.WriteString(" || ")
				}
			}
			str = str[i+1:]
			i = strings.IndexAny(str, "\r\n")
		}
		if str != "" {
			b.WriteString(`'` + strings.ReplaceAll(str, `'`, `''`) + `'`)
		}
		if dialect == DialectMySQL || dialect == DialectSQLServer {
			b.WriteString(")")
		}
		return b.String(), nil
	case time.Time:
		if dialect == DialectPostgres || dialect == DialectSQLServer {
			return `'` + v.Format(timestampWithTimezone) + `'`, nil
		}
		return `'` + v.UTC().Format(timestamp) + `'`, nil
	case int:
		return strconv.FormatInt(int64(v), 10), nil
	case int8:
		return strconv.FormatInt(int64(v), 10), nil
	case int16:
		return strconv.FormatInt(int64(v), 10), nil
	case int32:
		return strconv.FormatInt(int64(v), 10), nil
	case int64:
		return strconv.FormatInt(v, 10), nil
	case uint:
		return strconv.FormatUint(uint64(v), 10), nil
	case uint8:
		return strconv.FormatUint(uint64(v), 10), nil
	case uint16:
		return strconv.FormatUint(uint64(v), 10), nil
	case uint32:
		return strconv.FormatUint(uint64(v), 10), nil
	case uint64:
		return strconv.FormatUint(v, 10), nil
	case float32:
		return strconv.FormatFloat(float64(v), 'g', -1, 64), nil
	case float64:
		return strconv.FormatFloat(v, 'g', -1, 64), nil
	case sql.NamedArg:
		return Sprint(dialect, v.Value)
	case sql.NullBool:
		if !v.Valid {
			return "NULL", nil
		}
		if v.Bool {
			if dialect == DialectSQLServer {
				return "1", nil
			}
			return "TRUE", nil
		}
		if dialect == DialectSQLServer {
			return "0", nil
		}
		return "FALSE", nil
	case sql.NullFloat64:
		if !v.Valid {
			return "NULL", nil
		}
		return strconv.FormatFloat(v.Float64, 'g', -1, 64), nil
	case sql.NullInt64:
		if !v.Valid {
			return "NULL", nil
		}
		return strconv.FormatInt(v.Int64, 10), nil
	case sql.NullInt32:
		if !v.Valid {
			return "NULL", nil
		}
		return strconv.FormatInt(int64(v.Int32), 10), nil
	case sql.NullString:
		if !v.Valid {
			return "NULL", nil
		}
		return Sprint(dialect, v.String)
	case sql.NullTime:
		if !v.Valid {
			return "NULL", nil
		}
		if dialect == DialectPostgres || dialect == DialectSQLServer {
			return `'` + v.Time.Format(timestampWithTimezone) + `'`, nil
		}
		return `'` + v.Time.UTC().Format(timestamp) + `'`, nil
	case driver.Valuer:
		vv, err := v.Value()
		if err != nil {
			return "", fmt.Errorf("error when calling Value(): %w", err)
		}
		switch vv.(type) {
		case int64, float64, bool, []byte, string, time.Time, nil:
			return Sprint(dialect, vv)
		default:
			return "", fmt.Errorf("invalid driver.Value type %T (must be one of int64, float64, bool, []byte, string, time.Time, nil)", vv)
		}
	}
	rv := reflect.ValueOf(v)
	if rv.Kind() == reflect.Pointer {
		rv = rv.Elem()
		if !rv.IsValid() {
			return "NULL", nil
		}
	}
	switch v := rv.Interface().(type) {
	case bool, []byte, string, time.Time, int, int8, int16, int32, int64, uint,
		uint8, uint16, uint32, uint64, float32, float64, sql.NamedArg,
		sql.NullBool, sql.NullFloat64, sql.NullInt64, sql.NullInt32,
		sql.NullString, sql.NullTime, driver.Valuer:
		return Sprint(dialect, v)
	default:
		return "", fmt.Errorf("%T has no SQL representation", v)
	}
}

// isExpandableSlice checks if a value is an expandable slice.
func isExpandableSlice(value any) bool {
	// treat byte slices as a special case that we never want to expand
	if _, ok := value.([]byte); ok {
		return false
	}
	valueType := reflect.TypeOf(value)
	if valueType == nil {
		return false
	}
	return valueType.Kind() == reflect.Slice
}

// expandSlice expands a slice value into Output. Make sure the value is an
// expandable slice first by checking it with isExpandableSlice().
func expandSlice(ctx context.Context, dialect string, buf *bytes.Buffer, args *[]any, params map[string][]int, value any) error {
	slice := reflect.ValueOf(value)
	var err error
	for i := 0; i < slice.Len(); i++ {
		if i > 0 {
			buf.WriteString(", ")
		}
		arg := slice.Index(i).Interface()
		if v, ok := arg.(SQLWriter); ok {
			err = v.WriteSQL(ctx, dialect, buf, args, params)
			if err != nil {
				return err
			}
			continue
		}
		switch dialect {
		case DialectPostgres, DialectSQLite:
			buf.WriteString("$" + strconv.Itoa(len(*args)+1))
		case DialectSQLServer:
			buf.WriteString("@p" + strconv.Itoa(len(*args)+1))
		default:
			buf.WriteString("?")
		}
		arg, err = preprocessValue(dialect, arg)
		if err != nil {
			return err
		}
		*args = append(*args, arg)
	}
	return nil
}

// writeNamedArg writes an sql.NamedArg into the Output.
func writeNamedArg(ctx context.Context, dialect string, buf *bytes.Buffer, args *[]any, params map[string][]int, namedArg sql.NamedArg) error {
	if w, ok := namedArg.Value.(SQLWriter); ok {
		return w.WriteSQL(ctx, dialect, buf, args, params)
	}
	if isExpandableSlice(namedArg.Value) {
		return expandSlice(ctx, dialect, buf, args, params, namedArg.Value)
	}
	var err error
	namedArg.Value, err = preprocessValue(dialect, namedArg.Value)
	if err != nil {
		return err
	}
	paramIndices := params[namedArg.Name]
	if len(paramIndices) > 0 {
		index := paramIndices[0]
		switch dialect {
		case DialectSQLite:
			(*args)[index] = namedArg
			buf.WriteString("$" + namedArg.Name)
			return nil
		case DialectPostgres:
			(*args)[index] = namedArg.Value
			buf.WriteString("$" + strconv.Itoa(index+1))
			return nil
		case DialectSQLServer:
			(*args)[index] = namedArg
			buf.WriteString("@" + namedArg.Name)
			return nil
		default:
			for _, index := range paramIndices {
				(*args)[index] = namedArg.Value
			}
		}
	}
	switch dialect {
	case DialectSQLite:
		*args = append(*args, namedArg)
		if params != nil {
			index := len(*args) - 1
			params[namedArg.Name] = []int{index}
		}
		buf.WriteString("$" + namedArg.Name)
	case DialectPostgres:
		*args = append(*args, namedArg.Value)
		index := len(*args) - 1
		if params != nil {
			params[namedArg.Name] = []int{index}
		}
		buf.WriteString("$" + strconv.Itoa(index+1))
	case DialectSQLServer:
		*args = append(*args, namedArg)
		if params != nil {
			index := len(*args) - 1
			params[namedArg.Name] = []int{index}
		}
		buf.WriteString("@" + namedArg.Name)
	default:
		*args = append(*args, namedArg.Value)
		if params != nil {
			index := len(*args) - 1
			params[namedArg.Name] = append(paramIndices, index)
		}
		buf.WriteString("?")
	}
	return nil
}

// writeOrdinalValue writes an ordinal value into the Output. The
// ordinalIndices map is there to keep track of which ordinal values we have
// already appended to args (which we do not want to append again).
func writeOrdinalValue(ctx context.Context, dialect string, buf *bytes.Buffer, args *[]any, params map[string][]int, values []any, ordinal int, ordinalIndices map[int]int) error {
	index := ordinal - 1
	if index < 0 || index >= len(values) {
		return fmt.Errorf("ordinal parameter {%d} is out of bounds", ordinal)
	}
	value := values[index]
	if namedArg, ok := value.(sql.NamedArg); ok {
		return writeNamedArg(ctx, dialect, buf, args, params, namedArg)
	}
	if w, ok := value.(SQLWriter); ok {
		return w.WriteSQL(ctx, dialect, buf, args, params)
	}
	if isExpandableSlice(value) {
		return expandSlice(ctx, dialect, buf, args, params, value)
	}
	var err error
	value, err = preprocessValue(dialect, value)
	if err != nil {
		return err
	}
	switch dialect {
	case DialectSQLite, DialectPostgres, DialectSQLServer:
		index, ok := ordinalIndices[ordinal]
		if !ok {
			*args = append(*args, value)
			index = len(*args) - 1
			ordinalIndices[ordinal] = index
		}
		switch dialect {
		case DialectSQLite, DialectPostgres:
			buf.WriteString("$" + strconv.Itoa(index+1))
		case DialectSQLServer:
			buf.WriteString("@p" + strconv.Itoa(index+1))
		}
	default:
		err := WriteValue(ctx, dialect, buf, args, params, value)
		if err != nil {
			return err
		}
	}
	return nil
}

// lookupParam returns the SQL representation of a paramName (inside the args
// slice).
func lookupParam(dialect string, args []any, paramName []rune, namedIndices map[string]int, runningArgsIndex int) (paramValue string, err error) {
	var maybeNum string
	if paramName[0] == '@' && dialect == DialectSQLServer && len(paramName) >= 2 && (paramName[1] == 'p' || paramName[1] == 'P') {
		maybeNum = string(paramName[2:])
	} else {
		maybeNum = string(paramName[1:])
	}

	// is paramName an anonymous parameter?
	if maybeNum == "" {
		if paramName[0] != '?' {
			return "", fmt.Errorf("parameter name missing")
		}
		paramValue, err = Sprint(dialect, args[runningArgsIndex])
		if err != nil {
			return "", err
		}
		return paramValue, nil
	}

	// is paramName an ordinal paramater?
	ordinal, err := strconv.Atoi(maybeNum)
	if err == nil {
		index := ordinal - 1
		if index < 0 || index >= len(args) {
			return "", fmt.Errorf("args index %d out of bounds", ordinal)
		}
		paramValue, err = Sprint(dialect, args[index])
		if err != nil {
			return "", err
		}
		return paramValue, nil
	}

	// if we reach here, we know that the paramName is not an ordinal parameter
	// i.e. it is a named parameter
	if dialect == DialectPostgres || dialect == DialectMySQL {
		return "", fmt.Errorf("%s does not support %s named parameter", dialect, string(paramName))
	}
	index, ok := namedIndices[string(paramName[1:])]
	if !ok {
		return "", fmt.Errorf("named parameter %s not provided", string(paramName))
	}
	if index < 0 || index >= len(args) {
		return "", fmt.Errorf("args index %d out of bounds", ordinal)
	}
	paramValue, err = Sprint(dialect, args[index])
	if err != nil {
		return "", err
	}
	return paramValue, nil
}

// Expression represents an SQL expression.
type Expression struct {
	Format string
	Values []any
}

// Expr creates a new Expression using Writef syntax.
func Expr(format string, values ...any) Expression {
	return Expression{Format: format, Values: values}
}

func (expr Expression) Append(format string, values ...any) Expression {
	expr.Format += " " + format
	expr.Values = append(expr.Values, values...)
	return expr
}

// WriteSQL implements the SQLWriter interface.
func (expr Expression) WriteSQL(ctx context.Context, dialect string, buf *bytes.Buffer, args *[]any, params map[string][]int) error {
	err := Writef(ctx, dialect, buf, args, params, expr.Format, expr.Values)
	if err != nil {
		return err
	}
	return nil
}

type DialectExpression struct {
	Default any
	Cases   []DialectCase
}

type DialectCase struct {
	Dialect string
	Result  any
}

// WriteSQL implements the SQLWriter interface.
func (e DialectExpression) WriteSQL(ctx context.Context, dialect string, buf *bytes.Buffer, args *[]any, params map[string][]int) error {
	for _, dialectCase := range e.Cases {
		if dialect == dialectCase.Dialect {
			return WriteValue(ctx, dialect, buf, args, params, dialectCase.Result)
		}
	}
	return WriteValue(ctx, dialect, buf, args, params, e.Default)
}

// Parameter is identical to sql.NamedArg, but implements the Field interface.
type Parameter sql.NamedArg

// Param creates a new Parameter.
func Param(name string, value any) Parameter {
	return Parameter{Name: name, Value: value}
}

// BytesParam creates a new Parameter using a []byte value.
func BytesParam(name string, b []byte) Parameter {
	return Parameter{Name: name, Value: b}
}

// BoolParam creates a new Parameter from a bool value.
func BoolParam(name string, b bool) Parameter {
	return Parameter{Name: name, Value: b}
}

// IntParam creates a new Parameter from an int value.
func IntParam(name string, num int) Parameter {
	return Parameter{Name: name, Value: num}
}

// Int64Param creates a new Parameter from an int64 value.
func Int64Param(name string, num int64) Parameter {
	return Parameter{Name: name, Value: num}
}

// Float64Param creates a new NumberParameter from an float64 value.
func Float64Param(name string, num float64) Parameter {
	return Parameter{Name: name, Value: num}
}

// StringParam creates a new Parameter from a string value.
func StringParam(name string, s string) Parameter {
	return Parameter{Name: name, Value: s}
}

// TimeParam creates a new Parameter from a time.Time value.
func TimeParam(name string, t time.Time) Parameter {
	return Parameter{Name: name, Value: &Timestamp{Time: t, Valid: !t.IsZero()}}
}

// UUIDParam creates a new Parameter. It wraps the value with UUID().
func UUIDParam(name string, value [16]byte) Parameter {
	return Parameter{Name: name, Value: UUID(value)}
}

// WriteSQL implements the SQLWriter interface.
func (p Parameter) WriteSQL(ctx context.Context, dialect string, buf *bytes.Buffer, args *[]any, params map[string][]int) error {
	return writeNamedArg(ctx, dialect, buf, args, params, sql.NamedArg(p))
}

// SQLite keyword reference: https://www.sqlite.org/lang_keywords.html
var sqliteKeywords = map[string]struct{}{
	"abort": {}, "action": {}, "add": {}, "after": {}, "all": {}, "alter": {},
	"always": {}, "analyze": {}, "and": {}, "as": {}, "asc": {}, "attach": {},
	"autoincrement": {}, "before": {}, "begin": {}, "between": {}, "by": {},
	"cascade": {}, "case": {}, "cast": {}, "check": {}, "collate": {}, "column": {},
	"commit": {}, "conflict": {}, "constraint": {}, "create": {}, "cross": {},
	"current": {}, "current_date": {}, "current_time": {}, "current_timestamp": {},
	"database": {}, "default": {}, "deferrable": {}, "deferred": {}, "delete": {},
	"desc": {}, "detach": {}, "distinct": {}, "do": {}, "drop": {}, "each": {},
	"else": {}, "end": {}, "escape": {}, "except": {}, "exclude": {}, "exclusive": {},
	"exists": {}, "explain": {}, "fail": {}, "filter": {}, "first": {}, "following": {},
	"for": {}, "foreign": {}, "from": {}, "full": {}, "generated": {}, "glob": {},
	"group": {}, "groups": {}, "having": {}, "if": {}, "ignore": {}, "immediate": {},
	"in": {}, "index": {}, "indexed": {}, "initially": {}, "inner": {}, "insert": {},
	"instead": {}, "intersect": {}, "into": {}, "is": {}, "isnull": {}, "join": {},
	"key": {}, "last": {}, "left": {}, "like": {}, "limit": {}, "match": {},
	"materialized": {}, "natural": {}, "no": {}, "not": {}, "nothing": {}, "notnull": {},
	"null": {}, "nulls": {}, "of": {}, "offset": {}, "on": {}, "or": {}, "order": {},
	"others": {}, "outer": {}, "over": {}, "partition": {}, "plan": {}, "pragma": {},
	"preceding": {}, "primary": {}, "query": {}, "raise": {}, "range": {},
	"recursive": {}, "references": {}, "regexp": {}, "reindex": {}, "release": {},
	"rename": {}, "replace": {}, "restrict": {}, "returning": {}, "right": {},
	"rollback": {}, "row": {}, "rows": {}, "savepoint": {}, "select": {}, "set": {},
	"table": {}, "temp": {}, "temporary": {}, "then": {}, "ties": {}, "to": {},
	"transaction": {}, "trigger": {}, "unbounded": {}, "union": {}, "unique": {},
	"update": {}, "using": {}, "vacuum": {}, "values": {}, "view": {}, "virtual": {},
	"when": {}, "where": {}, "window": {}, "with": {}, "without": {},
}

// Postgres keyword reference:
// https://www.postgresql.org/docs/current/sql-keywords-appendix.html
var postgresKeywords = map[string]struct{}{
	"all": {}, "analyse": {}, "analyze": {}, "and": {}, "any": {}, "array": {}, "as": {},
	"asc": {}, "asymmetric": {}, "authorization": {}, "binary": {}, "both": {},
	"case": {}, "cast": {}, "check": {}, "collate": {}, "collation": {}, "column": {},
	"concurrently": {}, "constraint": {}, "create": {}, "cross": {},
	"current_catalog": {}, "current_date": {}, "current_role": {},
	"current_schema": {}, "current_time": {}, "current_timestamp": {},
	"current_user": {}, "default": {}, "deferrable": {}, "desc": {}, "distinct": {},
	"do": {}, "else": {}, "end": {}, "except": {}, "false": {}, "fetch": {}, "for": {},
	"foreign": {}, "freeze": {}, "from": {}, "full": {}, "grant": {}, "group": {},
	"having": {}, "ilike": {}, "in": {}, "initially": {}, "inner": {}, "intersect": {},
	"into": {}, "is": {}, "isnull": {}, "join": {}, "lateral": {}, "leading": {},
	"left": {}, "like": {}, "limit": {}, "localtime": {}, "localtimestamp": {},
	"natural": {}, "not": {}, "notnull": {}, "null": {}, "offset": {}, "on": {},
	"only": {}, "or": {}, "order": {}, "outer": {}, "overlaps": {}, "placing": {},
	"primary": {}, "references": {}, "returning": {}, "right": {}, "select": {},
	"session_user": {}, "similar": {}, "some": {}, "symmetric": {}, "table": {},
	"tablesample": {}, "then": {}, "to": {}, "trailing": {}, "true": {}, "union": {},
	"unique": {}, "user": {}, "using": {}, "variadic": {}, "verbose": {}, "when": {},
	"where": {}, "window": {}, "with": {},
}

// MySQL keyword reference:
// https://dev.mysql.com/doc/refman/8.0/en/keywords.html
var mysqlKeywords = map[string]struct{}{
	"accessible": {}, "add": {}, "all": {}, "alter": {}, "analyze": {}, "and": {},
	"as": {}, "asc": {}, "asensitive": {}, "before": {}, "between": {}, "bigint": {},
	"binary": {}, "blob": {}, "both": {}, "by": {}, "call": {}, "cascade": {}, "case": {},
	"change": {}, "char": {}, "character": {}, "check": {}, "collate": {}, "column": {},
	"condition": {}, "constraint": {}, "continue": {}, "convert": {}, "create": {},
	"cross": {}, "cube": {}, "cume_dist": {}, "current_date": {}, "current_time": {},
	"current_timestamp": {}, "current_user": {}, "cursor": {}, "database": {},
	"databases": {}, "day_hour": {}, "day_microsecond": {}, "day_minute": {},
	"day_second": {}, "dec": {}, "decimal": {}, "declare": {}, "default": {},
	"delayed": {}, "delete": {}, "dense_rank": {}, "desc": {}, "describe": {},
	"deterministic": {}, "distinct": {}, "distinctrow": {}, "div": {}, "double": {},
	"drop": {}, "dual": {}, "each": {}, "else": {}, "elseif": {}, "empty": {},
	"enclosed": {}, "escaped": {}, "except": {}, "exists": {}, "exit": {}, "explain": {},
	"false": {}, "fetch": {}, "first_value": {}, "float": {}, "float4": {}, "float8": {},
	"for": {}, "force": {}, "foreign": {}, "from": {}, "fulltext": {}, "function": {},
	"generated": {}, "get": {}, "grant": {}, "group": {}, "grouping": {}, "groups": {},
	"having": {}, "high_priority": {}, "hour_microsecond": {}, "hour_minute": {},
	"hour_second": {}, "if": {}, "ignore": {}, "in": {}, "index": {}, "infile": {},
	"inner": {}, "inout": {}, "insensitive": {}, "insert": {}, "int": {}, "int1": {},
	"int2": {}, "int3": {}, "int4": {}, "int8": {}, "integer": {}, "intersect": {},
	"interval": {}, "into": {}, "io_after_gtids": {}, "io_before_gtids": {}, "is": {},
	"iterate": {}, "join": {}, "json_table": {}, "key": {}, "keys": {}, "kill": {},
	"lag": {}, "last_value": {}, "lateral": {}, "lead": {}, "leading": {}, "leave": {},
	"left": {}, "like": {}, "limit": {}, "linear": {}, "lines": {}, "load": {},
	"localtime": {}, "localtimestamp": {}, "lock": {}, "long": {}, "longblob": {},
	"longtext": {}, "loop": {}, "low_priority": {}, "master_bind": {},
	"master_ssl_verify_server_cert": {}, "match": {}, "maxvalue": {}, "mediumblob": {},
	"mediumint": {}, "mediumtext": {}, "middleint": {}, "minute_microsecond": {},
	"minute_second": {}, "mod": {}, "modifies": {}, "natural": {}, "not": {},
	"no_write_to_binlog": {}, "nth_value": {}, "ntile": {}, "null": {}, "numeric": {},
	"of": {}, "on": {}, "optimize": {}, "optimizer_costs": {}, "option": {},
	"optionally": {}, "or": {}, "order": {}, "out": {}, "outer": {}, "outfile": {},
	"over": {}, "partition": {}, "percent_rank": {}, "precision": {}, "primary": {},
	"procedure": {}, "purge": {}, "range": {}, "rank": {}, "read": {}, "reads": {},
	"read_write": {}, "real": {}, "recursive": {}, "references": {}, "regexp": {},
	"release": {}, "rename": {}, "repeat": {}, "replace": {}, "require": {},
	"resignal": {}, "restrict": {}, "return": {}, "revoke": {}, "right": {}, "rlike": {},
	"row": {}, "rows": {}, "row_number": {}, "schema": {}, "schemas": {},
	"second_microsecond": {}, "select": {}, "sensitive": {}, "separator": {}, "set": {},
	"show": {}, "signal": {}, "smallint": {}, "spatial": {}, "specific": {}, "sql": {},
	"sqlexception": {}, "sqlstate": {}, "sqlwarning": {}, "sql_big_result": {},
	"sql_calc_found_rows": {}, "sql_small_result": {}, "ssl": {}, "starting": {},
	"stored": {}, "straight_join": {}, "system": {}, "table": {}, "terminated": {},
	"then": {}, "tinyblob": {}, "tinyint": {}, "tinytext": {}, "to": {}, "trailing": {},
	"trigger": {}, "true": {}, "undo": {}, "union": {}, "unique": {}, "unlock": {},
	"unsigned": {}, "update": {}, "usage": {}, "use": {}, "using": {}, "utc_date": {},
	"utc_time": {}, "utc_timestamp": {}, "values": {}, "varbinary": {}, "varchar": {},
	"varcharacter": {}, "varying": {}, "virtual": {}, "when": {}, "where": {},
	"while": {}, "window": {}, "with": {}, "write": {}, "xor": {}, "year_month": {},
	"zerofill": {},
}

// SQLServer keyword reference:
// https://learn.microsoft.com/en-us/sql/t-sql/language-elements/reserved-keywords-transact-sql?view=sql-server-ver16
var sqlserverKeywords = map[string]struct{}{
	"add": {}, "external": {}, "procedure": {}, "all": {}, "fetch": {}, "public": {},
	"alter": {}, "file": {}, "raiserror": {}, "and": {}, "fillfactor": {}, "read": {},
	"any": {}, "for": {}, "readtext": {}, "as": {}, "foreign": {}, "reconfigure": {},
	"asc": {}, "freetext": {}, "references": {}, "authorization": {},
	"freetexttable": {}, "replication": {}, "backup": {}, "from": {}, "restore": {},
	"begin": {}, "full": {}, "restrict": {}, "between": {}, "function": {}, "return": {},
	"break": {}, "goto": {}, "revert": {}, "browse": {}, "grant": {}, "revoke": {},
	"bulk": {}, "group": {}, "right": {}, "by": {}, "having": {}, "rollback": {},
	"cascade": {}, "holdlock": {}, "rowcount": {}, "case": {}, "identity": {},
	"rowguidcol": {}, "check": {}, "identity_insert": {}, "rule": {}, "checkpoint": {},
	"identitycol": {}, "save": {}, "close": {}, "if": {}, "schema": {}, "clustered": {},
	"in": {}, "securityaudit": {}, "coalesce": {}, "index": {}, "select": {},
	"collate": {}, "inner": {}, "semantickeyphrasetable": {}, "column": {},
	"insert": {}, "semanticsimilaritydetailstable": {}, "commit": {}, "intersect": {},
	"semanticsimilaritytable": {}, "compute": {}, "into": {}, "session_user": {},
	"constraint": {}, "is": {}, "set": {}, "contains": {}, "join": {}, "setuser": {},
	"containstable": {}, "key": {}, "shutdown": {}, "continue": {}, "kill": {},
	"some": {}, "convert": {}, "left": {}, "statistics": {}, "create": {}, "like": {},
	"system_user": {}, "cross": {}, "lineno": {}, "table": {}, "current": {}, "load": {},
	"tablesample": {}, "current_date": {}, "merge": {}, "textsize": {},
	"current_time": {}, "national": {}, "then": {}, "current_timestamp": {},
	"nocheck": {}, "to": {}, "current_user": {}, "nonclustered": {}, "top": {},
	"cursor": {}, "not": {}, "tran": {}, "database": {}, "null": {}, "transaction": {},
	"dbcc": {}, "nullif": {}, "trigger": {}, "deallocate": {}, "of": {}, "truncate": {},
	"declare": {}, "off": {}, "try_convert": {}, "default": {}, "offsets": {},
	"tsequal": {}, "delete": {}, "on": {}, "union": {}, "deny": {}, "open": {},
	"unique": {}, "desc": {}, "opendatasource": {}, "unpivot": {}, "disk": {},
	"openquery": {}, "update": {}, "distinct": {}, "openrowset": {}, "updatetext": {},
	"distributed": {}, "openxml": {}, "use": {}, "double": {}, "option": {}, "user": {},
	"drop": {}, "or": {}, "values": {}, "dump": {}, "order": {}, "varying": {},
	"else": {}, "outer": {}, "view": {}, "end": {}, "over": {}, "waitfor": {},
	"errlvl": {}, "percent": {}, "when": {}, "escape": {}, "pivot": {}, "where": {},
	"except": {}, "plan": {}, "while": {}, "exec": {}, "precision": {}, "with": {},
	"execute": {}, "primary": {}, "within group": {}, "exists": {}, "print": {},
	"writetext": {}, "exit": {}, "proc": {},
}
