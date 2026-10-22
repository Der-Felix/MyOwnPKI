#!/usr/bin/env bash
# failed-tests.sh LOG [SUMMARY] – turn the failures in a `go test` log into
# GitHub annotations (::error::) and a Markdown block for the step summary.
#
# Annotations of a public repository can be read without signing in (also
# through the API: check-runs/<id>/annotations); the raw job log can't.
#
# For every "--- FAIL: <name>" line: the test name and its indented output
# (file:line: message), at most MAX_LINES lines, at most MAX_ANNOTATIONS
# annotations. Without -v, go test prints a test's output after its FAIL
# line; with -v before it, after "=== RUN/CONT/NAME <name>" – both work. A
# panic, a data race report or a build error is attached to the failed test
# it belongs to, or reported on its own. File paths in `go test` output are
# relative to the package; the package comes from the "FAIL <import path>"
# line that ends it, so the annotation also points at the file.
#
# LOG may also be `go test -json` output (the race job): it is regrouped per
# package into the text above. If a package started and never ended – the
# run was killed or timed out – one more annotation lists those packages and
# the tests that had started and not ended, latest first.
#
# failed-tests.sh --text – a filter from `go test -json` to readable text for
# the job log while the run goes: "started <package>", the "ok" line of a
# package that passed, everything of a package that failed, and at the end
# the last lines of packages that never ended. (Plain `go test ./...` holds a
# package's output back until the package ends; -json streams it, so a run
# that is killed still shows what was running.)
#
# Uses only POSIX awk features (Ubuntu's default awk is mawk).
set -euo pipefail

# The go test -json reader. mode=stream: the --text filter. mode=group: the
# text per package for the parser below, and the unfinished report into the
# file "report".
# shellcheck disable=SC2016 # an awk program: its $ belong to awk
json_awk='
function hexval(h,   i, v) {
	v = 0; h = tolower(h)
	for (i = 1; i <= 4; i++) v = v * 16 + index("0123456789abcdef", substr(h, i, 1)) - 1
	return v
}
# The value of "key" in a test2json line, JSON escapes resolved.
function jget(line, key,   p, s, out, c, v) {
	p = index(line, "\"" key "\":")
	if (p == 0) return ""
	s = substr(line, p + length(key) + 3)
	if (substr(s, 1, 1) != "\"") { match(s, /^[^,}]*/); return substr(s, 1, RLENGTH) }
	s = substr(s, 2); out = ""
	while (s != "") {
		match(s, /^[^"\\]*/)
		out = out substr(s, 1, RLENGTH); s = substr(s, RLENGTH + 1)
		if (substr(s, 1, 1) != "\\") break # the closing quote, or a line cut off by a kill
		c = substr(s, 2, 1); s = substr(s, 3)
		if (c == "n") out = out "\n"
		else if (c == "t") out = out "\t"
		else if (c == "r") out = out "\r"
		else if (c == "u") { v = hexval(substr(s, 1, 4)); s = substr(s, 5); out = out ((v >= 32 && v < 127) ? sprintf("%c", v) : "?") }
		else if (c != "b" && c != "f") out = out c
	}
	return out
}
function hms(t) { return length(t) >= 19 ? substr(t, 12, 8) : "?" }
function tail(s, n,   a, m, i, r) {
	m = split(s, a, "\n"); if (m > 0 && a[m] == "") m--
	r = ""
	for (i = (m > n ? m - n + 1 : 1); i <= m; i++) r = r "    " a[i] "\n"
	return r
}
function parent(k,   o, kp, op) {
	split(k, kp, SUBSEP)
	for (o in running) { split(o, op, SUBSEP); if (op[1] == kp[1] && index(op[2], kp[2] "/") == 1) return 1 }
	return 0
}
function show(s) { printf "%s", s; if (mode == "stream") fflush() }
{ sub(/\r$/, "") }
substr($0, 1, 1) != "{" { show($0 "\n"); next }
{
	act = jget($0, "Action"); pkg = jget($0, "Package"); tst = jget($0, "Test"); seq++
	if (act == "build-output") { show(jget($0, "Output")); next } # names ImportPath, not Package
	if (pkg == "") next
	if (!(pkg in seen)) { seen[pkg] = 1; order[++np] = pkg; first[pkg] = jget($0, "Time") }
	last = jget($0, "Time")
	if (act == "output") {
		out = jget($0, "Output"); buf[pkg] = buf[pkg] out
		if (tst == "") pkgout[pkg] = pkgout[pkg] out
		next
	}
	if (tst != "") {
		k = pkg SUBSEP tst
		if (act == "run") { running[k] = seq; rtime[k] = last; state[k] = "" }
		else if (act == "pause") state[k] = "  (paused: a parallel test waiting for its turn)"
		else if (act == "cont") state[k] = ""
		else if (act == "pass" || act == "fail" || act == "skip") delete running[k]
		next
	}
	if (act == "start" && mode == "stream") show("started  " pkg "\n")
	if (act == "pass" || act == "fail" || act == "skip") {
		ended[pkg] = 1
		show((mode == "stream" && act != "fail") ? pkgout[pkg] : buf[pkg])
		delete buf[pkg]; delete pkgout[pkg]
	}
}
END {
	r = ""; nu = 0
	for (i = 1; i <= np; i++) {
		p = order[i]
		if (p in ended) continue
		nu++
		if (mode == "stream") show("not finished: " p " – its last output:\n" tail(buf[p], 20))
		else show(buf[p])
		r = r "\n  " p "  (started " hms(first[p]) ")"
		if (nu <= 3) lasts = lasts "\nLast output of " p ":\n" tail(buf[p], 10)
	}
	if (mode == "stream" || nu == 0 || report == "") exit
	r = "go test did not finish: " nu " package(s) started and never ended (last event " hms(last) "):" r
	n = 0
	for (k in running) if (!parent(k)) ks[++n] = k
	for (i = 1; i < n; i++) for (j = i + 1; j <= n; j++) if (running[ks[j]] > running[ks[i]]) { t = ks[i]; ks[i] = ks[j]; ks[j] = t }
	r = r "\n\nTests that started and did not end, latest first:"
	for (i = 1; i <= n && i <= max_tests; i++) { split(ks[i], kp, SUBSEP); r = r "\n  " hms(rtime[ks[i]]) "  " kp[1] "  " kp[2] state[ks[i]] }
	if (n > max_tests) r = r "\n  … " (n - max_tests) " more"
	if (n == 0) r = r "\n  (none – the packages were starting or between tests)"
	printf "%s\n%s", r, lasts > report
}'

if [ "${1:-}" = "--text" ]; then
	exec awk -v mode=stream "$json_awk"
fi

log=${1:?usage: failed-tests.sh LOG [SUMMARY] | failed-tests.sh --text}
summary=${2:-}
module=$(awk '$1 == "module" { print $2; exit }' go.mod 2>/dev/null || true)

text=$log
report=
first=$(grep -m1 -v '^[[:space:]]*$' "$log" || true)
case $first in
'{"'*)
	tmp=$(mktemp -d)
	trap 'rm -rf "$tmp"' EXIT
	text=$tmp/test.log report=$tmp/unfinished.txt
	awk -v mode=group -v report="$report" -v max_tests="${MAX_LINES:-40}" "$json_awk" "$log" > "$text"
	;;
esac

awk -v max_lines="${MAX_LINES:-40}" -v max_ann="${MAX_ANNOTATIONS:-10}" \
    -v summary="$summary" -v module="$module" '
function indent(s) { match(s, /^[ \t]*/); return RLENGTH }
# Workflow command escaping: data (%, CR, LF); properties also ":" and ",".
function esc_data(s) { gsub(/%/, "%25", s); gsub(/\r/, "%0D", s); gsub(/\n/, "%0A", s); return s }
function esc_prop(s) { s = esc_data(s); gsub(/:/, "%3A", s); gsub(/,/, "%2C", s); return s }
function append(old, s) { return old == "" ? s : old "\n" s }
function has_child(b,   c) {
	for (c = 1; c <= n; c++) if (c != b && index(names[c], names[b] "/") == 1) return 1
	return 0
}
{ sub(/\r$/, "") }

# A package ends: its blocks get the import path.
/^(FAIL|ok)[ \t]+[^ \t]/ {
	for (b = done + 1; b <= n; b++) pkg[b] = $2
	done = n; open = 0; collecting = 0; fresh = 0
	next
}
/^[ \t]*--- FAIL: / {
	name = $0; sub(/^[ \t]*--- FAIL: /, "", name); sub(/ \([0-9.]+s\)$/, "", name)
	n++; names[n] = name; ind[n] = indent($0); after[n] = ""; cnt[n] = 0
	open = n; collecting = 0; fresh = n
	next
}
/^[ \t]*--- (PASS|SKIP): / { open = 0; fresh = 0; next }
# -v: who is speaking now.
/^=== (RUN|CONT|NAME|PAUSE) / { current = $3; open = 0; fresh = 0; next }
# Output after a FAIL line (without -v).
open && indent($0) > ind[open] && $0 !~ /^[ \t]*$/ {
	if (cnt[open] < max_lines) after[open] = append(after[open], $0)
	else if (cnt[open] == max_lines) after[open] = append(after[open], "…")
	cnt[open]++
	next
}
{ open = 0 }
# Output before a FAIL line (-v), by test name.
current != "" && /^[ \t]+[^ \t]/ {
	if (bcnt[current] < max_lines) before[current] = append(before[current], $0)
	bcnt[current]++
	next
}
# A crash or a build error: a panic right after a FAIL line belongs to that
# test (go test prints "--- FAIL" first); anything else (a data race report
# comes before its FAIL line, a build error has none) is reported on its own.
/^panic: / || /^WARNING: DATA RACE/ || /^fatal error: / || /^# [^ ]/ {
	if (!collecting) { k++; crash[k] = $0; ccnt[k] = 1; owner[k] = fresh; fresh = 0; collecting = 1; next }
}
collecting {
	if (ccnt[k] < max_lines) { crash[k] = append(crash[k], $0); ccnt[k]++ }
	next
}
END {
	for (c = 1; c <= k; c++) if (owner[c] && extra[owner[c]] == "") extra[owner[c]] = crash[c]
	shown = 0
	for (b = 1; b <= n && shown < max_ann; b++) {
		text = after[b]
		if (text == "") text = before[names[b]]
		if (extra[b] != "") text = append(text, extra[b])
		# A parent that failed only because a subtest did: the subtest says it.
		if (text == "" && has_child(b)) continue
		if (text == "") text = "(no output – see the step log)"
		# The last file:line of the block – usually the failing check.
		ref = ""; rest = text
		while (match(rest, /[A-Za-z0-9_.-]+_test\.go:[0-9]+/)) {
			ref = substr(rest, RSTART, RLENGTH); rest = substr(rest, RSTART + RLENGTH)
		}
		props = "title=" esc_prop("FAIL " names[b] (pkg[b] != "" ? " (" pkg[b] ")" : ""))
		if (ref != "" && module != "" && index(pkg[b], module) == 1) {
			split(ref, parts, ":")
			dir = substr(pkg[b], length(module) + 2)
			props = props ",file=" esc_prop((dir != "" ? dir "/" : "") parts[1]) ",line=" parts[2]
		}
		printf "::error %s::%s\n", props, esc_data(names[b] "\n" text)
		if (summary != "") printf "#### `%s`%s\n\n```text\n%s\n```\n\n", names[b], (pkg[b] != "" ? " – " pkg[b] : ""), text >> summary
		shown++
	}
	for (c = 1; c <= k && shown < max_ann; c++) {
		if (owner[c]) continue
		printf "::error title=%s::%s\n", esc_prop("go test failed"), esc_data(crash[c])
		if (summary != "") printf "#### go test failed\n\n```text\n%s\n```\n\n", crash[c] >> summary
		shown++
	}
	if (n > max_ann) printf "::warning title=%s::%s\n", esc_prop("more failed tests"), esc_data((n - max_ann) " more – see the step log")
	if (summary != "") printf "_%d failed test(s) in the log._\n", n >> summary
}
' "$text"

if [ -n "$report" ] && [ -s "$report" ]; then
	data=$(cat "$report")
	if [ -n "$summary" ]; then
		# shellcheck disable=SC2016 # Markdown backticks, not a command
		printf '\n#### go test did not finish\n\n```text\n%s\n```\n' "$data" >> "$summary"
	fi
	data=${data//%/%25}
	data=${data//$'\r'/%0D}
	printf '::error title=go test aborted::%s\n' "${data//$'\n'/%0A}"
fi
