package callback

import (
	"bytes"
	"embed"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
)

//go:embed templates/*.html
var embeddedFS embed.FS

var requiredTemplates = []string{"success.html", "error.html"}

type successData struct {
	Email      string
	SessionID  string
	Hostname   string
	ServerName string
}

type errorData struct {
	Title      string
	Message    string
	StatusCode int
	SessionID  string
	Hostname   string
	ServerName string
}

// loadTemplates parses HTML templates from the embedded FS or from an override
// directory on disk. It validates that both required templates are present.
func loadTemplates(overrideDir string) (*template.Template, error) {
	var tmpl *template.Template
	var err error

	if overrideDir != "" {
		info, statErr := os.Stat(overrideDir)
		if statErr != nil {
			return nil, fmt.Errorf("templates-dir: %w", statErr)
		}
		if !info.IsDir() {
			return nil, fmt.Errorf("templates-dir: not a directory: %s", overrideDir)
		}

		// Pre-check that all required files exist before parsing.
		var missing []string
		var paths []string
		for _, name := range requiredTemplates {
			p := filepath.Join(overrideDir, name)
			if _, err := os.Stat(p); err != nil {
				if os.IsNotExist(err) {
					missing = append(missing, name)
				} else {
					return nil, fmt.Errorf("templates-dir: %s: %w", name, err)
				}
			} else {
				paths = append(paths, p)
			}
		}
		if len(missing) > 0 {
			return nil, fmt.Errorf("templates-dir: missing required templates: %v", missing)
		}

		tmpl, err = template.ParseFiles(paths...)
	} else {
		tmpl, err = template.ParseFS(embeddedFS, "templates/*.html")
	}
	if err != nil {
		return nil, fmt.Errorf("parse templates: %w", err)
	}

	for _, name := range requiredTemplates {
		if tmpl.Lookup(name) == nil {
			return nil, fmt.Errorf("missing required template: %s", name)
		}
	}
	return tmpl, nil
}

func setCommonHeaders(w http.ResponseWriter, contentType string) {
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
}

func (s *Server) renderSuccess(w http.ResponseWriter, email, sessionID string) {
	var buf bytes.Buffer
	data := successData{
		Email:      email,
		SessionID:  sessionID,
		Hostname:   s.hostname,
		ServerName: s.cfg.ServerName,
	}
	if err := s.tmpl.ExecuteTemplate(&buf, "success.html", data); err != nil {
		slog.Error("render success template failed", "error", err)
		setCommonHeaders(w, "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintln(w, "authenticated")
		return
	}
	setCommonHeaders(w, "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = buf.WriteTo(w)
}

func (s *Server) renderError(w http.ResponseWriter, status int, title, message, sessionID string) {
	var buf bytes.Buffer
	data := errorData{
		Title:      title,
		Message:    message,
		StatusCode: status,
		SessionID:  sessionID,
		Hostname:   s.hostname,
		ServerName: s.cfg.ServerName,
	}
	if err := s.tmpl.ExecuteTemplate(&buf, "error.html", data); err != nil {
		slog.Error("render error template failed", "error", err)
		setCommonHeaders(w, "text/plain; charset=utf-8")
		w.WriteHeader(status)
		_, _ = fmt.Fprintln(w, message)
		return
	}
	setCommonHeaders(w, "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = buf.WriteTo(w)
}
