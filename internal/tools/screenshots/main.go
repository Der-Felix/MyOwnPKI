// Command screenshots renders the UI prototype (dev mode, fixture data) with a
// headless Chromium-based browser (Edge, Chrome, Chromium) and writes
// losslessly optimized PNGs for the README to docs/screenshots.
//
// Screenshots are regenerated at milestones only, not on every UI change:
// every new image stays in the Git history for good (frontend.md).
//
// Usage: task screenshots [-- -browser PATH]
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/web"
	"github.com/Der-Felix/MyOwnPKI/internal/web/view"
)

// sizeTarget is the size each image should stay below; larger images are
// reported, not rejected.
const sizeTarget = 150 * 1024

type shot struct {
	name string
	path string
	dark bool
}

var shots = []shot{
	{"dashboard", "/", false},
	{"certificates", "/certificates", false},
	{"certificate-detail", "/certificates/c-0102", false},
	{"issue-wizard", "/certificates/new", false},
	{"authorities", "/authorities", false},
	{"dashboard-dark", "/", true},
}

func main() {
	os.Exit(run(os.Stdout, os.Stderr))
}

func run(stdout, stderr io.Writer) int {
	browser := flag.String("browser", os.Getenv("MYOWNPKI_BROWSER"),
		"path to Edge, Chrome or Chromium (default: $MYOWNPKI_BROWSER, then auto-detect)")
	out := flag.String("out", filepath.Join("docs", "screenshots"), "output directory")
	width := flag.Int("width", 1400, "window width in CSS pixels")
	height := flag.Int("height", 900, "window height in CSS pixels")
	flag.Parse()

	if *browser == "" {
		*browser = findBrowser()
	}
	if *browser == "" {
		fmt.Fprintln(stderr, "no Chromium-based browser found; pass -browser PATH or set MYOWNPKI_BROWSER")
		return 1
	}
	if err := os.MkdirAll(*out, 0o750); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}

	light, dark, stop, err := startServers()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	defer stop()

	fmt.Fprintf(stdout, "browser: %s\n", *browser)
	failed := false
	for _, s := range shots {
		base := light
		if s.dark {
			base = dark
		}
		file := filepath.Join(*out, s.name+".png")
		if err := capture(*browser, base+s.path, file, *width, *height); err != nil {
			fmt.Fprintf(stderr, "FAILED %s: %v\n", s.name, err)
			failed = true
			continue
		}
		before, after, err := optimizeFile(file)
		if err != nil {
			fmt.Fprintf(stderr, "FAILED %s: optimize: %v\n", s.name, err)
			failed = true
			continue
		}
		note := ""
		if after > sizeTarget {
			note = "  (above the 150 KB target)"
		}
		fmt.Fprintf(stdout, "ok     %-20s %4d KB -> %4d KB%s\n", s.name+".png", before/1024, after/1024, note)
	}
	if failed {
		return 1
	}
	return 0
}

// startServers serves the dev-mode UI on two loopback ports: the second one
// adds the appearance cookie for the dark theme to every request, so the
// product needs no screenshot-only switch.
func startServers() (light, dark string, stop func(), err error) {
	handler, err := web.NewHandler(web.Options{Dev: true, Logger: slog.New(slog.DiscardHandler)})
	if err != nil {
		return "", "", nil, err
	}
	prefs := view.DefaultPrefs()
	prefs.Theme = view.ThemeDark
	darkHandler := withCookie(handler, view.PrefsCookie+"="+prefs.String())

	var servers []*http.Server
	stop = func() {
		for _, srv := range servers {
			_ = srv.Close()
		}
	}
	var urls []string
	for _, h := range []http.Handler{handler, darkHandler} {
		ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
		if err != nil {
			stop()
			return "", "", nil, err
		}
		srv := &http.Server{Handler: h, ReadHeaderTimeout: 5 * time.Second}
		servers = append(servers, srv)
		go func() { _ = srv.Serve(ln) }()
		urls = append(urls, "http://"+ln.Addr().String())
	}
	return urls[0], urls[1], stop, nil
}

// withCookie sets the Cookie request header (name=value) before h sees it.
func withCookie(h http.Handler, cookie string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Header.Set("Cookie", cookie)
		h.ServeHTTP(w, r)
	})
}

// capture loads url in a headless browser with a fresh profile and saves a
// screenshot of the window to file.
func capture(browser, url, file string, width, height int) error {
	abs, err := filepath.Abs(file)
	if err != nil {
		return err
	}
	_ = os.Remove(abs)
	profile, err := os.MkdirTemp("", "myownpki-shot-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(profile) }()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	// The browser path is chosen by the developer running the task.
	cmd := exec.CommandContext(ctx, browser, //nolint:gosec // see above
		"--headless=new",
		"--no-first-run",
		"--no-default-browser-check",
		"--disable-extensions",
		"--hide-scrollbars",
		"--force-device-scale-factor=1",
		"--user-data-dir="+profile,
		"--window-size="+strconv.Itoa(width)+","+strconv.Itoa(height),
		"--screenshot="+abs,
		url,
	)
	output, runErr := cmd.CombinedOutput()
	if info, err := os.Stat(abs); err == nil && info.Size() > 0 {
		return nil
	}
	if runErr == nil {
		runErr = errors.New("browser wrote no screenshot")
	}
	return fmt.Errorf("%w\n%s", runErr, output)
}

// findBrowser returns the first Chromium-based browser found in the usual
// install locations, or "".
func findBrowser() string {
	var candidates []string
	switch runtime.GOOS {
	case "windows":
		for _, env := range []string{"ProgramFiles(x86)", "ProgramFiles", "LOCALAPPDATA"} {
			if dir := os.Getenv(env); dir != "" {
				candidates = append(candidates,
					filepath.Join(dir, "Microsoft", "Edge", "Application", "msedge.exe"),
					filepath.Join(dir, "Google", "Chrome", "Application", "chrome.exe"))
			}
		}
	case "darwin":
		candidates = []string{
			"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
			"/Applications/Chromium.app/Contents/MacOS/Chromium",
			"/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
		}
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil { //nolint:gosec // fixed install locations under ProgramFiles/LOCALAPPDATA
			return c
		}
	}
	for _, name := range []string{"chromium", "chromium-browser", "google-chrome", "google-chrome-stable", "microsoft-edge"} {
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
	}
	return ""
}
