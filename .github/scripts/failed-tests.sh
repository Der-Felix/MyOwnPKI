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
# Uses only POSIX awk features (Ubuntu's default awk is mawk).
set -euo pipefail

log=${1:?usage: failed-tests.sh LOG [SUMMARY]}
summary=${2:-}
module=$(awk '$1 == "module" { print $2; exit }' go.mod 2>/dev/null || true)

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
' "$log"
