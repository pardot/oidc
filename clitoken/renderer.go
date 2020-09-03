package clitoken

import (
	"html/template"
	"io"
)

// Templates
var (
	tmplError = template.Must(template.New("").Parse(`
	  <h1>Error</h1>
		<hr>
		{{.}}
	`))

	tmplTokenIssued = template.Must(template.New("").Parse(`
	  <h1>Success</h1>
		<hr>
		Return to the terminal to continue.
	`))
)

type Renderer interface {
	RenderLocalTokenSourceTokenIssued(w io.Writer) error
	RenderLocalTokenSourceError(w io.Writer, message string) error
}

type renderer struct{}

// RenderLocalTokenSourceTokenIssued renders a success message after issuing a token.
func (r *renderer) RenderLocalTokenSourceTokenIssued(w io.Writer) error {
	return tmplTokenIssued.Execute(w, nil)
}

// RenderLocalTokenSourceError renders an unrecoverable error.
func (r *renderer) RenderLocalTokenSourceError(w io.Writer, message string) error {
	return tmplError.Execute(w, message)
}
