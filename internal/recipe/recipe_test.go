package recipe

import (
	"slices"
	"strconv"
	"strings"
	"testing"
)

func TestNamesAndGet(t *testing.T) {
	t.Parallel()
	if got, want := Names(), []string{"apache2", "dovecot", "httpd", "nginx", "postfix", "proxmox"}; !slices.Equal(got, want) {
		t.Fatalf("Names() = %v, want %v", got, want)
	}
	if _, ok := Get("lighttpd"); ok {
		t.Error("an unknown recipe was found")
	}
	// Get hands out copies: changing one must not change the next.
	a, _ := Get("nginx")
	a.Hooks[0].Command[0] = "/tmp/evil"
	a.SandboxWrite[0] = "/etc"
	a.Notes = append(a.Notes, "x")
	b, _ := Get("nginx")
	if b.Hooks[0].Command[0] != "/usr/sbin/nginx" || b.SandboxWrite[0] != "/var/log/nginx" {
		t.Errorf("a modified copy leaked into the table: %+v", b)
	}
}

// liveTested names the recipes that ran on a live host (v0.3.5: nginx). Every
// other recipe is an example. A recipe joins this set only after a live test.
var liveTested = map[string]bool{"nginx": true}

// Every recipe is a complete, safe description; the agent's tests render each
// of them through the configuration validation as well.
func TestEveryRecipeIsWellFormed(t *testing.T) {
	t.Parallel()
	for _, name := range Names() {
		r, _ := Get(name)
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if r.Name != name || r.Summary == "" {
				t.Errorf("name %q summary %q", r.Name, r.Summary)
			}
			switch r.Profile {
			case "nginx":
				if !strings.HasPrefix(r.Dir, "/etc/ssl/myownpki/") || r.Fullchain != "" || r.Key != "" || r.Combined != "" {
					t.Errorf("nginx profile: dir %q files %q %q %q", r.Dir, r.Fullchain, r.Key, r.Combined)
				}
			case "file":
				oneFile := r.Combined != "" && r.Certificate == "" && r.Chain == "" && r.Fullchain == "" && r.Key == ""
				twoFiles := r.Combined == "" && r.Key != "" && (r.Certificate != "" || r.Fullchain != "")
				if r.Dir != "" || oneFile == twoFiles {
					t.Errorf("file profile: want the combined file alone, or a key with a certificate or fullchain: %+v", r)
				}
				for _, p := range []string{r.Certificate, r.Chain, r.Fullchain, r.Key, r.Combined} {
					if p != "" && !strings.HasPrefix(p, "/etc/ssl/myownpki/") {
						t.Errorf("file %q is not below /etc/ssl/myownpki/", p)
					}
				}
			default:
				t.Errorf("profile %q", r.Profile)
			}
			if mode, err := strconv.ParseUint(r.KeyMode, 8, 32); err != nil || mode&0o007 != 0 {
				t.Errorf("key mode %q gives rights to others", r.KeyMode)
			}
			if r.Owner != "root" {
				t.Errorf("owner %q", r.Owner)
			}
			names := map[string]bool{}
			for _, h := range r.Hooks {
				if names[h.Name] {
					t.Errorf("hook %q twice", h.Name)
				}
				names[h.Name] = true
				if len(h.Command) == 0 || !strings.HasPrefix(h.Command[0], "/") {
					t.Errorf("hook %q: the first element must be an absolute path: %v", h.Name, h.Command)
				}
			}
			for _, ref := range []string{r.TestHook, r.ReloadHook} {
				if ref != "" && !names[ref] {
					t.Errorf("hook %q is referenced but not defined", ref)
				}
			}
			if r.ReloadHook == "" {
				t.Error("a recipe without a reload hook leaves the service on the old certificate")
			}
			if r.Check != "" && !strings.HasPrefix(r.Check, "127.0.0.1:") {
				t.Errorf("check %q must be local", r.Check)
			}
			for _, d := range r.SandboxWrite {
				if !strings.HasPrefix(d, "/") || strings.Count(d, "/") < 2 {
					t.Errorf("sandbox directory %q is too broad", d)
				}
			}
			// A recipe is an example until it ran on a live host; an example must
			// say what to verify.
			if liveTested[name] == r.Example || (r.Example && len(r.Notes) == 0) {
				t.Errorf("example flag %v, %d notes", r.Example, len(r.Notes))
			}
		})
	}
}

// The facts of the table in docs/PHASE3.md §11.2.
func TestRecipeFacts(t *testing.T) {
	t.Parallel()
	pve, _ := Get("proxmox")
	if pve.Check != "127.0.0.1:8006" || !slices.Equal(pve.SandboxWrite, []string{"/etc/pve"}) || pve.TestHook != "" {
		t.Errorf("proxmox: %+v", pve)
	}
	if got := strings.Join(pve.Hooks[0].Command, " "); got != "/usr/bin/pvenode cert set /etc/ssl/myownpki/pve/fullchain.pem /etc/ssl/myownpki/pve/privkey.pem --force 1 --restart 1" {
		t.Errorf("proxmox hook: %s", got)
	}
	dove, _ := Get("dovecot")
	if dove.Check != "127.0.0.1:993" || dove.Hooks[0].Command[0] != "/usr/bin/doveconf" {
		t.Errorf("dovecot: %+v", dove)
	}
	postfix, _ := Get("postfix")
	if postfix.Check != "" || postfix.Hooks[0].Command[1] != "check" {
		t.Errorf("postfix: %+v", postfix)
	}
	// Apache: one recipe per distribution family, named after the unit.
	for _, tc := range []struct {
		name, test, reload, logs string
	}{
		{"apache2", "/usr/sbin/apache2ctl configtest", "/usr/bin/systemctl reload apache2", "/var/log/apache2"},
		{"httpd", "/usr/sbin/httpd -t", "/usr/bin/systemctl reload httpd", "/var/log/httpd"},
	} {
		r, _ := Get(tc.name)
		hooks := map[string]string{}
		for _, h := range r.Hooks {
			hooks[h.Name] = strings.Join(h.Command, " ")
		}
		if r.Profile != "nginx" || r.Dir != "/etc/ssl/myownpki/{name}" || r.KeyMode != "0600" || r.Group != "" ||
			r.Check != "127.0.0.1:443" || r.LowPorts || !slices.Equal(r.SandboxWrite, []string{tc.logs}) || !r.Example ||
			r.TestHook != tc.name+"-test" || r.ReloadHook != tc.name+"-reload" || len(r.Hooks) != 2 ||
			hooks[r.TestHook] != tc.test || hooks[r.ReloadHook] != tc.reload {
			t.Errorf("%s: %+v", tc.name, r)
		}
		if notes := strings.Join(r.Notes, "\n"); !strings.Contains(notes, "SSLCertificateFile /etc/ssl/myownpki/<name>/fullchain.pem") ||
			!strings.Contains(notes, "SSLCertificateKeyFile /etc/ssl/myownpki/<name>/privkey.pem") || !strings.Contains(notes, "match") {
			t.Errorf("%s: the notes lack the vhost lines or the configtest caveat:\n%s", tc.name, notes)
		}
	}
	httpd, _ := Get("httpd")
	if !strings.Contains(strings.Join(httpd.Notes, "\n"), "restorecon") {
		t.Errorf("httpd: the notes do not mention the SELinux label: %v", httpd.Notes)
	}
	nginx, _ := Get("nginx")
	if !nginx.LowPorts || nginx.Check != "127.0.0.1:443" || !slices.Equal(nginx.SandboxWrite, []string{"/var/log/nginx"}) {
		t.Errorf("nginx: %+v", nginx)
	}
}

// {name} stands for the deployment name and nothing else: it is in paths only,
// never in a hook, a check or a directory the sandbox opens.
func TestNameAppearsOnlyInPaths(t *testing.T) {
	t.Parallel()
	for _, name := range Names() {
		r, _ := Get(name)
		for _, h := range r.Hooks {
			if strings.Contains(strings.Join(h.Command, " "), "{") {
				t.Errorf("%s: hook %s has a placeholder: %v", name, h.Name, h.Command)
			}
		}
		for _, v := range append([]string{r.Check, r.Owner, r.Group, r.KeyMode}, r.SandboxWrite...) {
			if strings.Contains(v, "{") {
				t.Errorf("%s: placeholder in %q", name, v)
			}
		}
		for _, p := range []string{r.Dir, r.Certificate, r.Chain, r.Fullchain, r.Key, r.Combined} {
			if strings.Contains(strings.ReplaceAll(p, "{name}", ""), "{") {
				t.Errorf("%s: unknown placeholder in %q", name, p)
			}
		}
		// A file shared by every deployment of a recipe (no {name}) would
		// collide at the second one; only the single-service recipes may do that.
		if r.Profile == "file" && r.Combined != "" && !strings.Contains(r.Combined, "{name}") {
			t.Errorf("%s: the combined file has no {name}", name)
		}
	}
}
