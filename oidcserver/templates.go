package oidcserver

import (
	"fmt"
	"html/template"
	"io"
	"net/http"
	"sort"
	"strings"

	packr "github.com/gobuffalo/packr/v2"
)

var (
	webTemplates = packr.New("templates", "./web/templates")
	webStatic    = packr.New("static", "./web/static")
)

const (
	tmplApproval = "approval.html"
	tmplLogin    = "login.html"
	tmplOOB      = "oob.html"
	tmplError    = "error.html"
)

type templates struct {
	loginTmpl    *template.Template
	approvalTmpl *template.Template
	oobTmpl      *template.Template
	errorTmpl    *template.Template
}

func join(base, path string) string {
	b := strings.HasSuffix(base, "/")
	p := strings.HasPrefix(path, "/")
	switch {
	case b && p:
		return base + path[1:]
	case b || p:
		return base + path
	default:
		return base + "/" + path
	}
}

// loadTemplates parses the expected templates from the provided directory.
func loadTemplates(issuer, logoURL, issuerURL string) (*templates, error) {
	funcs := map[string]interface{}{
		"issuer": func() string { return issuer },
		"logo":   func() string { return logoURL },
		"url":    func(s string) string { return join(issuerURL, s) },
		"lower":  strings.ToLower,
	}

	tmpls := template.New("").Funcs(funcs)

	for _, tf := range webTemplates.List() {
		tb, err := webTemplates.FindString(tf)
		if err != nil {
			return nil, err
		}
		_, err = tmpls.New(tf).Parse(tb)
		if err != nil {
			return nil, err
		}
	}

	return &templates{
		loginTmpl:    tmpls.Lookup(tmplLogin),
		approvalTmpl: tmpls.Lookup(tmplApproval),
		oobTmpl:      tmpls.Lookup(tmplOOB),
		errorTmpl:    tmpls.Lookup(tmplError),
	}, nil
}

var scopeDescriptions = map[string]string{
	"offline_access": "Have offline access",
	"profile":        "View basic profile information",
	"email":          "View your email address",
}

type connectorInfo struct {
	ID   string
	Name string
	URL  string
}

type byName []connectorInfo

func (n byName) Len() int           { return len(n) }
func (n byName) Less(i, j int) bool { return n[i].Name < n[j].Name }
func (n byName) Swap(i, j int)      { n[i], n[j] = n[j], n[i] }

func (t *templates) login(w http.ResponseWriter, connectors []connectorInfo) error {
	sort.Sort(byName(connectors))
	data := struct {
		Connectors []connectorInfo
	}{connectors}
	return renderTemplate(w, t.loginTmpl, data)
}

func (t *templates) approval(w http.ResponseWriter, authReqID, username, clientName string, scopes []string) error {
	accesses := []string{}
	for _, scope := range scopes {
		access, ok := scopeDescriptions[scope]
		if ok {
			accesses = append(accesses, access)
		}
	}
	sort.Strings(accesses)
	data := struct {
		User      string
		Client    string
		AuthReqID string
		Scopes    []string
	}{username, clientName, authReqID, accesses}
	return renderTemplate(w, t.approvalTmpl, data)
}

func (t *templates) oob(w http.ResponseWriter, code string) error {
	data := struct {
		Code string
	}{code}
	return renderTemplate(w, t.oobTmpl, data)
}

func (t *templates) err(w http.ResponseWriter, errCode int, errMsg string) error {
	w.WriteHeader(errCode)
	data := struct {
		ErrType string
		ErrMsg  string
	}{http.StatusText(errCode), errMsg}
	if err := t.errorTmpl.Execute(w, data); err != nil {
		return fmt.Errorf("Error rendering template %s: %s", t.errorTmpl.Name(), err)
	}
	return nil
}

// small io.Writer utility to determine if executing the template wrote to the underlying response writer.
type writeRecorder struct {
	wrote bool
	w     io.Writer
}

func (w *writeRecorder) Write(p []byte) (n int, err error) {
	w.wrote = true
	return w.w.Write(p)
}

func renderTemplate(w http.ResponseWriter, tmpl *template.Template, data interface{}) error {
	wr := &writeRecorder{w: w}
	if err := tmpl.Execute(wr, data); err != nil {
		if !wr.wrote {
			// TODO(ericchiang): replace with better internal server error.
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
		return fmt.Errorf("Error rendering template %s: %s", tmpl.Name(), err)
	}
	return nil
}
