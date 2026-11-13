package main

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"image"
	"image/color"
	"image/png"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func encodePNG(t *testing.T, img image.Image) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := (&png.Encoder{CompressionLevel: png.NoCompression}).Encode(&buf, img); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func decodePNG(t *testing.T, data []byte) image.Image {
	t.Helper()
	img, err := png.Decode(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	return img
}

// gradient has width*height distinct opaque colors when both are <= 256.
func gradient(width, height int) *image.NRGBA {
	img := image.NewNRGBA(image.Rect(0, 0, width, height))
	for y := range height {
		for x := range width {
			img.SetNRGBA(x, y, color.NRGBA{R: uint8(x), G: uint8(y), B: 0x80, A: 0xff})
		}
	}
	return img
}

// stripes looks like a UI screenshot without antialiasing: a large image
// with only a few colors.
func stripes(width, height int) *image.NRGBA {
	colors := []color.NRGBA{{0xff, 0xff, 0xff, 0xff}, {0x24, 0x24, 0x24, 0xff}, {0x0f, 0x5c, 0x99, 0xff}, {0xe0, 0xe0, 0xe0, 0xff}}
	img := image.NewNRGBA(image.Rect(0, 0, width, height))
	for y := range height {
		for x := range width {
			img.SetNRGBA(x, y, colors[(x/7+y/5)%len(colors)])
		}
	}
	return img
}

func TestOptimizeIsLossless(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		img       image.Image
		paletted  bool
		wantSmall bool
	}{
		{"few colors become a palette", stripes(400, 300), true, true},
		{"many colors stay RGB", gradient(64, 64), false, true},
		// 256 colors in 16x16 pixels: the palette costs more than it saves;
		// optimizeFile then keeps the original file.
		{"palette at the 256 limit", gradient(16, 16), true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			in := encodePNG(t, tt.img)
			out, err := optimize(in)
			if err != nil {
				t.Fatal(err)
			}
			got := decodePNG(t, out)
			if !samePixels(tt.img, got) {
				t.Fatal("pixels changed")
			}
			if _, ok := got.(*image.Paletted); ok != tt.paletted {
				t.Errorf("paletted = %v, want %v", ok, tt.paletted)
			}
			if tt.wantSmall && len(out) >= len(in) {
				t.Errorf("not smaller: %d -> %d bytes", len(in), len(out))
			}
		})
	}
}

func TestSamePixelsDetectsChange(t *testing.T) {
	t.Parallel()
	a, b := gradient(8, 8), gradient(8, 8)
	b.SetNRGBA(3, 3, color.NRGBA{A: 0xff})
	if samePixels(a, b) {
		t.Error("a changed pixel was not detected")
	}
}

// TestServersShowTheRealUI: the demo instance behind the screenshot servers –
// the sign-in page without session and without anything about the instance,
// the unseal page sealed, the dashboard light and dark; neutral names only.
func TestServersShowTheRealUI(t *testing.T) {
	t.Parallel()
	in, err := newInstance(t.Context(), filepath.Join(t.TempDir(), "data"))
	if err != nil {
		t.Fatal(err)
	}
	defer in.close()
	bases, stop, err := startServers(in)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	get := func(url string) string {
		t.Helper()
		resp, err := http.Get(url) //nolint:noctx,gosec // test against the local screenshot servers
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		return string(body)
	}
	if login := get(bases[anonymous] + "/login"); !strings.Contains(login, `name="password"`) || strings.Contains(login, "DEMO") {
		t.Error("sign-in page")
	}
	if unseal := get(bases[sealed] + "/unseal"); !strings.Contains(unseal, `name="passphrase"`) {
		t.Error("unseal page while sealed")
	}
	if err := in.ring.Unseal(t.Context(), []byte(in.passphrase), console); err != nil {
		t.Fatal(err)
	}
	for kind, want := range map[viewKind]string{light: `data-theme="light"`, dark: `data-theme="dark"`} {
		html := get(bases[kind] + "/certificates")
		if !strings.Contains(html, want) || !strings.Contains(html, "nas.homelab.example") || strings.Contains(html, "DEV MODE") {
			t.Errorf("view %d: theme or sample data missing", kind)
		}
	}
	host, _ := os.Hostname()
	if html := get(bases[light] + "/authorities"); !strings.Contains(html, "O=Homelab") || (host != "" && strings.Contains(strings.ToLower(html), strings.ToLower(host))) {
		t.Error("the CAs must be named neutrally, without the host name")
	}
}

// registeredGETRoutes reads the GET patterns of registerApp from its source:
// a ServeMux can't list its routes, and the UI must not gain a page the
// inventory does not know about.
func registeredGETRoutes(t *testing.T) []string {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filepath.Join("..", "..", "web", "app.go"), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var routes []string
	ast.Inspect(file, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "registerApp" {
			return true
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			for _, arg := range call.Args {
				lit, ok := arg.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					continue
				}
				if pattern, err := strconv.Unquote(lit.Value); err == nil {
					if route, ok := strings.CutPrefix(pattern, "GET "); ok {
						routes = append(routes, route)
					}
				}
			}
			return true
		})
		return false
	})
	if len(routes) < 40 {
		t.Fatalf("found only %d GET routes in registerApp: the parser no longer understands it", len(routes))
	}
	return routes
}

// TestInventoryCoversEveryRoute: a new page in registerApp fails this test
// until it is in inventoryPages or, with a reason, in inventoryExcluded; a
// route that was removed fails it too.
func TestInventoryCoversEveryRoute(t *testing.T) {
	t.Parallel()
	registered := map[string]bool{}
	covered := inventoryRoutes()
	for _, r := range registeredGETRoutes(t) {
		registered[r] = true
		if !covered[r] {
			t.Errorf("GET %s is registered by registerApp but is neither in inventoryPages nor in inventoryExcluded (internal/tools/screenshots/inventory.go)", r)
		}
	}
	for r := range covered {
		if !registered[r] {
			t.Errorf("the inventory lists GET %s, which registerApp no longer registers", r)
		}
	}
	names := map[string]bool{}
	for _, p := range inventoryPages {
		if names[p.name] {
			t.Errorf("page name %q is used twice", p.name)
		}
		names[p.name] = true
		if p.kind != anonymous && p.kind != sealed && p.kind != light {
			t.Errorf("page %q: only anonymous, sealed and light pages are listed (dark is shot for each)", p.name)
		}
	}
	for r, why := range inventoryExcluded {
		if why == "" {
			t.Errorf("excluded route %s needs a reason", r)
		}
	}
}

// TestInventoryInstanceShowsData: with the inventory seeds every page the
// plan names answers 200 and shows data, not an empty state; the seeds go
// through the real services, so this also proves that they still fit them.
func TestInventoryInstanceShowsData(t *testing.T) {
	t.Parallel()
	in, err := newInstanceWith(t.Context(), filepath.Join(t.TempDir(), "data"), true)
	if err != nil {
		t.Fatal(err)
	}
	defer in.close()
	bases, stop, err := startServers(in)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	if err := in.ring.Unseal(t.Context(), []byte(in.passphrase), console); err != nil {
		t.Fatal(err)
	}
	get := func(path string) (int, string) {
		t.Helper()
		resp, err := http.Get(bases[light] + path) //nolint:noctx // test against the local screenshot servers
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		return resp.StatusCode, string(body)
	}
	for path, want := range map[string]string{
		"/reports":                       "Expiry",
		"/analysis":                      "Renewal loop",
		"/alerts":                        "Agent silent",
		"/endpoints":                     "ci-runner.homelab.example",
		"/agents":                        "proxy-02.homelab.example",
		"/agents/enrollments":            "printer.homelab.example",
		"/agents/" + in.agentID:          "proxy-01.homelab.example",
		"/domains/" + in.domainID:        "corp.example",
		"/acme/accounts/" + in.accountID: "mailto:admin@homelab.example",
		"/admin/users/" + in.userID:      "alex",
		"/hosts/add/" + in.enrollHost:    "printer.homelab.example",
	} {
		status, body := get(path)
		if status != http.StatusOK || !strings.Contains(body, want) {
			t.Errorf("GET %s: status %d, contains %q: %v", path, status, want, strings.Contains(body, want))
		}
	}
}
