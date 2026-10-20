package main

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"io"
	"net/http"
	"os"
	"path/filepath"
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
