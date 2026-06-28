package htmlreport

import (
	"html/template"
	"strings"
	"testing"

	"github.com/gmrtd/gmrtd/document"
)

func TestExecuteDocumentTemplateError(t *testing.T) {
	tmpl := template.Must(template.New("not-output").Parse(`hello`))

	out, err := executeDocumentTemplate(tmpl, &templateData{DocumentEx: &document.DocumentEx{}})
	if err == nil {
		t.Fatalf("expected error")
	}
	if out != nil {
		t.Fatalf("expected nil output")
	}
	if !strings.Contains(err.Error(), "ExecuteTemplate") {
		t.Fatalf("unexpected error: %s", err)
	}
}
