package agentpath

import "testing"

func TestBroad(t *testing.T) {
	t.Parallel()
	for p, want := range map[string]bool{
		"/": true, "/etc": true, "/etc/": true, "/usr": true, "/var": true, "/root": true, "/home": true, "/tmp": true, "/opt": true,
		"/srv": true, "/mnt": true, "/lib": true, "/lib64": true, "/proc/self": true, "/sys/kernel": true, "/dev/shm": true, "/etc/../etc": true,
		"/etc/ssl/myownpki": false, "/var/www/acme": false, "/var/log/nginx": false, "/srv/www": false, "/etc/nginx": false,
	} {
		if got := Broad(p); got != want {
			t.Errorf("Broad(%q) = %v, want %v", p, got, want)
		}
	}
}
