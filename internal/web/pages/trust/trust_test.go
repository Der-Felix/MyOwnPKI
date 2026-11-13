package trust_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/Der-Felix/MyOwnPKI/internal/trustkit"
	"github.com/Der-Felix/MyOwnPKI/internal/web/pages/trust"
	"github.com/Der-Felix/MyOwnPKI/internal/web/view"
)

// TestPageEscapes: every string of the view model is text. Markup, quotes and
// script in names, common names, steps, notes and commands come out escaped,
// whatever the data holds.
func TestPageEscapes(t *testing.T) {
	t.Parallel()
	const payload = `<script>alert(1)</script><img src=x onerror=alert(2)>"'&`
	ca := trust.CA{
		Name: payload, Kind: "Root CA", Root: true, Generation: 2, Current: false, CommonName: payload, Valid: payload,
		Fingerprint: payload, SHA1: payload,
		DER: "/ca/x/2.crt", PEM: "/ca/x/2.pem", FileDER: payload, FilePEM: payload, FileCER: payload,
		WinMachine: "/trust/x/2/machine.cmd", WinUser: "/trust/x/2/user.cmd", Profile: "/trust/x/2/profile.mobileconfig", FileProfile: payload,
	}
	block := trustkit.Block{Title: payload, Steps: []string{payload}, Lines: []string{payload, "  && " + payload}, Note: payload}
	var sections []trust.Section
	for _, p := range trustkit.Platforms() {
		sections = append(sections, trust.Section{ID: string(p), Title: payload, Roots: []trust.RootGuide{{CA: ca, Blocks: []trustkit.Block{block}}}})
	}
	d := trust.Data{
		Roots: []trust.CA{ca}, Intermediates: []trust.CA{ca}, Detected: payload, FirefoxHint: true, Sections: sections,
		Choices: []trust.Choice{{Label: payload, Href: "/?os=windows", Selected: true}},
	}
	var buf bytes.Buffer
	if err := trust.Page(view.Page{Title: payload}, d).Render(t.Context(), &buf); err != nil {
		t.Fatal(err)
	}
	page := buf.String()
	for _, bad := range []string{"<script", "<img src=x", "onerror=alert(2)>", `"'&`, "alert(1)</script>"} {
		if strings.Contains(strings.ToLower(page), strings.ToLower(bad)) {
			t.Errorf("the page contains %q unescaped", bad)
		}
	}
	if !strings.Contains(page, "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Error("the payload is missing: it should appear as escaped text")
	}
	if strings.Contains(page, " style=") || strings.Contains(page, "<style") {
		t.Error("inline style")
	}
}

// TestPageWithoutData: no CA and no platform is a complete page.
func TestPageWithoutData(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	if err := trust.Page(view.Page{Title: "Trust"}, trust.Data{}).Render(t.Context(), &buf); err != nil {
		t.Fatal(err)
	}
	page := buf.String()
	for _, want := range []string{"There is no root certificate authority to show yet.", "Before you install anything", "This page could not tell your system."} {
		if !strings.Contains(page, want) {
			t.Errorf("the page lacks %q", want)
		}
	}
	if strings.Contains(page, "Intermediate certificates") {
		t.Error("an empty list of intermediates has a heading")
	}
}
