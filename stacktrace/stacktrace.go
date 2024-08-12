package stacktrace

import (
	"errors"
	"fmt"
	"runtime"
	"strconv"
	"strings"
)

// Error represents an error annotated with a stack trace of callers.
type Error struct {
	Err     error
	Callers []string
}

var _ error = (*Error)(nil)

// New returns a wrapped error containing the stack trace of where New was
// called.
//
// This is an expensive function, do not use it in the hot path. Only use it on
// errors that are returned by operations that ordinarily are not expected to
// fail at all. The rationale is that only unexpected code paths should get
// stack traces (so we can debug their origin) and expected code paths do not
// get slowed down by the generation of expensive stack traces. By extension,
// do not use it on the error returned by an errgroup.Wait() because the error
// never originates from there, but instead from one of its child goroutines
// (where it should already have been wrapped).
func New(err error) error {
	_, ok := err.(*Error)
	if ok {
		return err
	}
	var e *Error
	if errors.As(err, &e) {
		return err
	}
	var pc [30]uintptr
	n := runtime.Callers(2, pc[:])
	frames := runtime.CallersFrames(pc[:n])
	callers := make([]string, 0, n)
	for frame, more := frames.Next(); more; frame, more = frames.Next() {
		callers = append(callers, frame.File+":"+strconv.Itoa(frame.Line))
	}
	return &Error{
		Err:     err,
		Callers: callers,
	}
}

// RecoverPanic converts a panic into an error containing a stack trace of
// where the panic occurred and writes it into the error pointer.
func RecoverPanic(err *error) {
	if v := recover(); v != nil {
		var pc [30]uintptr
		n := runtime.Callers(2, pc[:])
		frames := runtime.CallersFrames(pc[:n])
		callers := make([]string, 0, n)
		for frame, more := frames.Next(); more; frame, more = frames.Next() {
			callers = append(callers, frame.File+":"+strconv.Itoa(frame.Line))
		}
		if err != nil {
			*err = &Error{
				Err:     fmt.Errorf("panic: %v", v),
				Callers: callers,
			}
		}
	}
}

// Unwrap returns the underlying error.
func (e *Error) Unwrap() error {
	return e.Err
}

// Error implements the error interface.
func (e *Error) Error() string {
	var b strings.Builder
	last := len(e.Callers) - 1
	for i := last; i >= 0; i-- {
		if i < last {
			b.WriteString(" -> ")
		}
		b.WriteString(e.Callers[i])
	}
	if e.Err == nil {
		b.WriteString(": <nil>")
	} else {
		b.WriteString(": " + e.Err.Error())
	}
	return b.String()
}
