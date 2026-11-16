package agent

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/Der-Felix/MyOwnPKI/internal/recipe"
)

// Real Apache (Debian and Ubuntu package apache2) with the recipe "apache2"
// (docs/PHASE3.md section 17, step 69). Switch: MYOWNPKI_E2E_APACHE=1.
//
// Apache runs as the user of the test with its own configuration, pid file and
// a free loopback port. The test hook is the recipe's own command,
// /usr/sbin/apache2ctl, with "-f <config> -t" in place of "configtest": that
// is what apache2ctl runs for configtest (it calls apache2 -t), but it can be
// pointed at the test's configuration. The reload is apache2 -k graceful on
// the test's own pid file; the recipe's systemctl reload would touch the
// installed service.
const (
	apacheBinary  = "/usr/sbin/apache2"
	apacheModules = "/usr/lib/apache2/modules"
)

// What the notes of the apache2 recipe may say about the three observations.
const (
	apacheNoteRejects      = "configtest rejects a key that does not match the certificate"
	apacheNoteMissesKey    = "configtest does not detect a key that does not match the certificate"
	apacheNotePendingKey   = "it is not known to check that key and certificate match"
	apacheNoteSurvives     = "a failed reload leaves Apache serving the previous certificate"
	apacheNoteStops        = "a failed reload can stop Apache"
	apacheMismatchSerial   = 900
	apacheReloadMarkerName = "reloads.log"
)

type serviceHarness struct {
	r      *deployRig
	d      Deployment
	files  Files
	svc    *realService
	rec    recipe.Recipe
	marker string // one line per reload the agent issued
}

func newApacheHarness(t *testing.T) *serviceHarness {
	t.Helper()
	rec := requireRealService(t, "apache", envE2EApache, "apache2", apacheBinary,
		filepath.Join(apacheModules, "mod_ssl.so"), filepath.Join(apacheModules, "mod_mpm_event.so"))
	r := newServiceRig(t, rec)
	r.installOld(t)
	d := r.a.cfg.Deployments[0]
	d.Check = freeLoopbackAddress(t)
	r.a.cfg.Deployments[0] = d
	files := deploymentPaths(d)

	prefix := t.TempDir()
	for _, dir := range []string{"run", "htdocs"} {
		if err := os.Mkdir(filepath.Join(prefix, dir), 0o750); err != nil {
			t.Fatal(err)
		}
	}
	conf := filepath.Join(prefix, "apache2.conf")
	configuration := fmt.Sprintf(`ServerRoot %[1]q
ServerName localhost
DefaultRuntimeDir %[2]q
PidFile %[3]q
ErrorLog %[4]q
LogLevel notice
DocumentRoot %[5]q
LoadModule mpm_event_module %[6]s/mod_mpm_event.so
LoadModule ssl_module %[6]s/mod_ssl.so
StartServers 1
ServerLimit 2
ThreadsPerChild 5
MinSpareThreads 5
MaxSpareThreads 15
MaxRequestWorkers 10
Listen %[7]s
<VirtualHost %[7]s>
	ServerName %[8]s
	SSLEngine on
	SSLCertificateFile %[9]q
	SSLCertificateKeyFile %[10]q
</VirtualHost>
`, prefix, filepath.Join(prefix, "run"), filepath.Join(prefix, "run", "apache2.pid"), filepath.Join(prefix, "error.log"),
		filepath.Join(prefix, "htdocs"), apacheModules, d.Check, d.Names[0], files.Fullchain, files.Key)
	if err := os.WriteFile(conf, []byte(configuration), 0o600); err != nil {
		t.Fatal(err)
	}

	testHook := recipeHook(t, rec, rec.TestHook)
	marker := filepath.Join(prefix, apacheReloadMarkerName)
	r.a.cfg.Hooks["test"] = []string{testHook[0], "-f", conf, "-t"}
	r.a.cfg.Hooks["reload"] = reloadWrapper(marker, apacheBinary, "-f", conf, "-k", "graceful")
	r.a.runHookForTest = nil
	r.a.Sleep = sleep

	// The recipe's test command must accept a good configuration before the
	// experiments change anything.
	group := groups(r.a.cfg.Deployments)[0]
	if err := r.a.runTests(t.Context(), group); err != nil {
		t.Fatalf("the test hook of recipe apache2 rejects the good configuration of the test: %v", err)
	}
	svc := startRealService(t, "apache2", prefix, []string{apacheBinary, "-f", conf, "-DFOREGROUND"}, filepath.Join(prefix, "error.log"))
	svc.waitListening(t, d.Check)
	if _, err := r.a.checkServed(t.Context(), d, fingerprint(r.old[d.Name].Leaf.Raw)); err != nil {
		t.Fatalf("Apache does not serve the old certificate after it started: %v", err)
	}
	return &serviceHarness{r: r, d: d, files: files, svc: svc, rec: rec, marker: marker}
}

// TestApacheDeployProfile: the agent writes a new certificate through the
// recipe's layout, the test hook (apache2ctl, real) accepts it, Apache reloads
// gracefully, and the served certificate is the deployed one.
func TestApacheDeployProfile(t *testing.T) {
	h := newApacheHarness(t)
	results, err := h.r.a.RunPass(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].State != "deployed" {
		t.Fatalf("pass result: %+v", results)
	}
	if n := reloadCount(t, h.marker); n != 1 {
		t.Fatalf("the agent issued %d reloads, want 1", n)
	}
	next := h.r.next[h.d.Name].Leaf
	assertServes(t, h.d.Check, h.d.Names[0], next)
	if results[0].Fingerprint != fingerprint(next.Raw) {
		t.Fatalf("the result names %s, the service serves %s", results[0].Fingerprint, fingerprint(next.Raw))
	}
	h.r.assertFiles(t, h.r.next)
}

// TestApacheConfigtestOnKeyMismatch records what apache2ctl configtest does
// with a certificate whose key belongs to another certificate (lane A
// open point 1) and compares it with the notes of the recipe. Nothing is
// reloaded; the files are restored at the end.
func TestApacheConfigtestOnKeyMismatch(t *testing.T) {
	h := newApacheHarness(t)
	d := h.d
	newer := map[string]*Material{d.Name: testMaterial(t, d.Names[0], apacheMismatchSerial)}
	group := groups(h.r.a.cfg.Deployments)[0]
	journal, err := h.r.a.stageGroup(group, newer)
	if err != nil {
		t.Fatal(err)
	}
	corruptStaged(t, h.r, d, newer[d.Name], h.r.old[d.Name].Key)
	failure := h.r.a.runTests(t.Context(), group)

	result := "configtest passed although the key does not belong to the certificate"
	if failure != nil {
		result = "configtest failed on the mismatch: " + oneLine(failure.Error())
	}
	cause := errors.New("observation recorded")
	results, rollbackErr := h.r.a.rollback(t.Context(), group, journal, false, cause)
	if !errors.Is(rollbackErr, cause) || len(results) != 1 || results[0].State != "rolled_back" {
		t.Fatalf("restoring the files failed: %+v, %v", results, rollbackErr)
	}
	h.r.assertFiles(t, h.r.old)
	if n := reloadCount(t, h.marker); n != 0 {
		t.Fatalf("the observation reloaded Apache %d times", n)
	}
	noteClaim{
		recipe: "apache2", topic: "configtest with a certificate/key mismatch (apache2ctl -f <config> -t)", result: result,
		seen: failure != nil, ifSeen: apacheNoteRejects, ifNot: apacheNoteMissesKey, pending: apacheNotePendingKey,
	}.check(t)
	t.Log("the httpd recipe carries the same sentence; Apache httpd on the Red Hat family was not run here (live test)")
}
