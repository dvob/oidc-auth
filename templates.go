package oidcproxy

import (
	"bytes"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"time"
)

func (a *Authenticator) servePage(w http.ResponseWriter, templateName string, data any) {
	buf, err := a.renderPage(templateName, data)
	if err != nil {
		slog.Error("faild to serve page", "template_name", templateName, "err", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	w.Header().Add("Content-Type", "text/html")
	w.Write(buf)
}

// renderPage executes the given templateName with page.
func (a *Authenticator) renderPage(templateName string, data any) ([]byte, error) {
	tmpl, err := a.getTemplate(templateName)
	if err != nil {
		return nil, err
	}
	return executeTemplate(templateName, tmpl, data)
}

func (a *Authenticator) getTemplate(templateName string) (*template.Template, error) {
	if a.devMode {
		a.mu.Lock()
		defer a.mu.Unlock()
		templateFS := os.DirFS("templates")
		templates, err := parsePageTemplates(templateFS)
		if err != nil {
			return nil, fmt.Errorf("error parsing templates: %v", err)
		}
		a.templates = templates
	}
	tmpl := a.templates[templateName]
	if tmpl == nil {
		return nil, fmt.Errorf("BUG: a.templates[%q] not found", templateName)
	}
	return tmpl, nil
}

func executeTemplate(templateName string, tmpl *template.Template, data any) ([]byte, error) {
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		slog.Error("error executing template", "name", templateName, "err", err)
		return nil, err
	}
	return buf.Bytes(), nil
}

// templates and parsed together with the files in each base directory.
func parsePageTemplates(fsys fs.FS) (map[string]*template.Template, error) {
	matches, err := fs.Glob(fsys, "*.tmpl")
	if err != nil {
		return nil, err
	}

	templates := make(map[string]*template.Template)
	funcs := map[string]any{
		"timeFmt": func(t time.Time) string {
			return t.Format(time.RFC3339)
		},
	}
	for _, match := range matches {
		t, err := template.New(match).Funcs(funcs).ParseFS(fsys, match)
		if err != nil {
			return nil, fmt.Errorf("failed to parse %s: %v", match, err)
		}
		helperGlob := "shared/*.tmpl"
		if _, err := t.ParseFS(fsys, helperGlob); err != nil {
			return nil, fmt.Errorf("ParseFS(%q): %v", helperGlob, err)
		}
		templateName := match[:len(match)-len(".tmpl")]
		templates[templateName] = t
	}

	return templates, nil
}
