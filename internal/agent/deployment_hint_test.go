package agent

import (
	"context"
	"strings"
	"testing"
)

// The hint about log files and listen sockets is for hooks that open them:
// nginx -t does, a configuration check of Apache or HAProxy does not.
func TestHintOnlyForHooksThatOpenSocketsAndLogs(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		cmd  []string
		want bool
	}{
		{[]string{"/usr/sbin/nginx", "-t"}, true},
		{[]string{"/usr/sbin/nginx", "-s", "reload"}, true},
		{[]string{"/usr/sbin/apache2ctl", "configtest"}, false},
		{[]string{"/usr/sbin/apachectl", "-t"}, false},
		{[]string{"/usr/sbin/apache2ctl", "graceful"}, true},
		{[]string{"/usr/sbin/apache2ctl", "start"}, true},
		{[]string{"/usr/sbin/haproxy", "-c", "-f", "/etc/haproxy/haproxy.cfg"}, false},
		{[]string{"/usr/sbin/haproxy", "-f", "/etc/haproxy/haproxy.cfg", "-sf", "1"}, true},
		{[]string{"/usr/bin/systemctl", "reload", "nginx"}, false},
		{[]string{"/usr/sbin/httpd", "-t"}, false},
		{nil, false},
	} {
		if got := opensSocketsAndLogs(tc.cmd); got != tc.want {
			t.Errorf("%v: %v, want %v", tc.cmd, got, tc.want)
		}
	}
}

// The same through the command: a deployment whose test hook is a check-only
// form prints no hint on stderr, a starting form does.
func TestAddPrintsTheHintOnlyForHooksThatOpenSockets(t *testing.T) {
	for name, tc := range map[string]struct {
		args []string
		want bool
	}{
		"nginx -t":            {[]string{"nginx", "-t"}, true},
		"haproxy -c":          {[]string{"haproxy", "-c", "-f", "/etc/haproxy/haproxy.cfg"}, false},
		"apache2ctl check":    {[]string{"apache2ctl", "configtest"}, false},
		"haproxy starting":    {[]string{"haproxy", "-f", "/etc/haproxy/haproxy.cfg"}, true},
		"apache2ctl graceful": {[]string{"apache2ctl", "graceful"}, true},
	} {
		t.Run(name, func(t *testing.T) {
			f := freshFixture(t)
			cmd := append([]string{f.p("bin", tc.args[0])}, tc.args[1:]...)
			spec := DeploymentSpec{Name: "p", Dir: f.p("ssl", "p"), Hooks: []HookSpec{{Name: "check", Command: cmd}}, TestHook: "check", ACMEDirectory: recipeACME}
			if err := AddDeployment(context.Background(), AddOptions{EditOptions: f.edit(), Spec: spec}); err != nil {
				t.Fatal(err)
			}
			if got := strings.Contains(f.stderr.String(), "hint: hook"); got != tc.want {
				t.Errorf("hint printed = %v, want %v:\n%s", got, tc.want, f.stderr.String())
			}
		})
	}
}
