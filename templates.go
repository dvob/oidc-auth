package oidcproxy

import (
	"bytes"
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"sync"
	"time"
)

//go:embed templates/*
var templateFS embed.FS

type templateManager struct {
	dirs      []fs.FS
	templates map[string]*template.Template

	devMode bool
	mu      *sync.Mutex
}

func NewTemplateManager(directory string, devMode bool) (*templateManager, error) {
	var templates map[string]*template.Template

	builtInTemplates, err := fs.Sub(templateFS, "templates")
	if err != nil {
		return nil, err
	}

	dirs := []fs.FS{builtInTemplates}
	if directory != "" {
		dirs = append(dirs, os.DirFS(directory))
	}

	templates, err = parsePageTemplates(dirs...)
	if err != nil {
		return nil, err
	}

	return &templateManager{
		dirs:      dirs,
		templates: templates,
		devMode:   devMode,
		mu:        &sync.Mutex{},
	}, nil
}

func (t *templateManager) servePage(w http.ResponseWriter, templateName string, data any) {
	buf, err := t.renderPage(templateName, data)
	if err != nil {
		slog.Error("faild to serve page", "template_name", templateName, "err", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	w.Header().Add("Content-Type", "text/html")
	w.Write(buf)
}

// renderPage executes the given templateName with page.
func (t *templateManager) renderPage(templateName string, data any) ([]byte, error) {
	tmpl, err := t.getTemplate(templateName)
	if err != nil {
		return nil, err
	}
	return executeTemplate(templateName, tmpl, data)
}

func (t *templateManager) getTemplate(templateName string) (*template.Template, error) {
	if t.devMode {
		t.mu.Lock()
		defer t.mu.Unlock()
		var err error
		t.templates, err = parsePageTemplates(t.dirs...)
		if err != nil {
			return nil, fmt.Errorf("error parsing templates: %v", err)
		}
	}
	tmpl := t.templates[templateName]
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
func parsePageTemplates(dirs ...fs.FS) (map[string]*template.Template, error) {
	templates := make(map[string]*template.Template)
	funcs := map[string]any{
		"timeFmt": func(t time.Time) string {
			return t.Format(time.RFC3339)
		},
	}

	// TODO: make shared helpers from buitIn available in subsequent dirs

	for _, dir := range dirs {
		matches, err := fs.Glob(dir, "*.tmpl")
		if err != nil {
			return nil, err
		}

		for _, match := range matches {
			t, err := template.New(match).Funcs(funcs).ParseFS(dir, match)
			if err != nil {
				return nil, fmt.Errorf("failed to parse %s: %v", match, err)
			}
			helperGlob := "shared/*.tmpl"
			matches, _ := fs.Glob(dir, helperGlob)
			if len(matches) > 0 {
				if _, err := t.ParseFS(dir, helperGlob); err != nil {
					return nil, fmt.Errorf("ParseFS(%q): %v", helperGlob, err)
				}
			}
			templateName := match[:len(match)-len(".tmpl")]
			templates[templateName] = t
		}
	}

	return templates, nil
}
