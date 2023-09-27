package main

import (
	"log/slog"
	"net/http"
	"time"
)

func newLogHandler(next http.Handler) http.Handler {
	logger := slog.Default()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sw := newStatusResponseWriter(w)
		start := time.Now()
		next.ServeHTTP(sw, r)
		logger.LogAttrs(r.Context(), slog.LevelInfo,
			"", //TODO: what should be the message
			slog.String("src", r.RemoteAddr),
			slog.String("proto", r.Proto),
			slog.String("method", r.Method),
			slog.String("host", r.Host),
			slog.String("uri", r.RequestURI),
			slog.Int("code", sw.statusCode),
			slog.Duration("duration", time.Now().Sub(start)),
			slog.Int("bytes", sw.bytesWritten),
		)
	})
}

var _ http.ResponseWriter = (*statusResponseWriter)(nil)

type statusResponseWriter struct {
	http.ResponseWriter
	headerWritten bool
	statusCode    int
	bytesWritten  int
}

func newStatusResponseWriter(w http.ResponseWriter) *statusResponseWriter {
	return &statusResponseWriter{
		ResponseWriter: w,
		statusCode: 200,
	}
}

// Write implements http.ResponseWriter.
func (s *statusResponseWriter) Write(p []byte) (int, error) {
	n, err := s.ResponseWriter.Write(p)
	s.bytesWritten += n
	s.headerWritten = true
	return n, err
}

func (s *statusResponseWriter) Unwrap() http.ResponseWriter {
	return s.ResponseWriter
}

// WriteHeader implements http.ResponseWriter.
func (s *statusResponseWriter) WriteHeader(statusCode int) {
	s.ResponseWriter.WriteHeader(statusCode)

	if !s.headerWritten {
		s.statusCode = statusCode
		s.headerWritten = true
	}
}
