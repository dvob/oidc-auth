package oidcauth

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
)

type ErrorHandler func(w http.ResponseWriter, r *http.Request, err error)

func DefaultErrorHandler(getRequestID func(r *http.Request) string, logger *slog.Logger) ErrorHandler {
	return func(w http.ResponseWriter, r *http.Request, err error) {
		var serr *ServerErr
		if !errors.As(err, &serr) {
			serr = &ServerErr{HTTPStatusCode: http.StatusInternalServerError, Err: err}
		}

		// log error
		if serr.HTTPStatusCode > 499 {
			logger.ErrorContext(r.Context(), "server error", "err", err)
		} else {
			logger.InfoContext(r.Context(), "server error", "err", err)
		}

		responseText := http.StatusText(serr.HTTPStatusCode)
		if serr.ResponseText != "" {
			responseText = serr.ResponseText
		}
		if getRequestID != nil {
			requestID := getRequestID(r)
			responseText += " (RequestID: " + requestID + ")"
		}
		http.Error(w, responseText, serr.HTTPStatusCode)
	}
}

// ServerErr is a error which can be passed to error handler. It allows to
// control what message is shown to the user.
type ServerErr struct {
	HTTPStatusCode int    // HTTP status code
	ResponseText   string // Response text to the user
	Err            error  // wrapped error
}

func (s *ServerErr) Error() string {
	return fmt.Sprintf("%d (%s): %v", s.HTTPStatusCode, http.StatusText(s.HTTPStatusCode), s.Err)
}

func (s *ServerErr) Unwrap() error {
	return s.Err
}

// ErrMessage creates a ServerErr which uses message as response text for the
// user
func ErrMessage(httpCode int, message string, err error) *ServerErr {
	return &ServerErr{
		HTTPStatusCode: httpCode,
		ResponseText:   message,
		Err:            err,
	}
}

// ErrDirect creates a ServerErr which returns the actual error text to the
// user
func ErrDirect(httpCode int, err error) *ServerErr {
	return &ServerErr{
		HTTPStatusCode: httpCode,
		ResponseText:   err.Error(),
		Err:            err,
	}
}
