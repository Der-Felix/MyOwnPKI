package agent

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"unicode"
)

// The systemd drop-ins of the agent unit (docs/PHASE3.md §11.2). One model
// derives both files from agent.yaml and the file as found, so that setup,
// "deployment add|remove" and "sandbox sync" cannot disagree:
//
//   - 10-paths.conf holds ReadWritePaths= with state_dir, paths and
//     sandbox.write. Entries the operator added by hand stay (they are
//     "kept"), the agent adds what the configuration implies and never
//     removes anything unless it is told to (prune, or the paths it has just
//     taken out of agent.yaml).
//   - 20-low-ports.conf is written when sandbox.low_ports is true or a
//     challenge is standalone, removed only when sandbox.low_ports is false,
//     and otherwise left exactly as found.

const (
	dropinPathsName    = "10-paths.conf"
	dropinLowPortsName = "20-low-ports.conf"
	maxDropinSize      = 64 << 10

	errUnitPath = "cannot be written to a systemd drop-in (white space, quotes, % or control characters)"

	dropinHeader = "# Written by myownpki-agent from agent.yaml (state_dir, paths, sandbox.write).\n" +
		"# Entries you add here by hand are kept; \"myownpki-agent sandbox sync\" shows them.\n"
)

// DropinState is what is on disk in the unit's .service.d directory.
type DropinState struct {
	Paths        []byte
	HavePaths    bool
	LowPorts     []byte
	HaveLowPorts bool
}

// ReadDropins reads both drop-ins; a missing file or directory is not an error.
func ReadDropins(dir string) (DropinState, error) {
	var st DropinState
	var err error
	if st.Paths, st.HavePaths, err = readDropinFile(filepath.Join(dir, dropinPathsName)); err != nil {
		return st, err
	}
	st.LowPorts, st.HaveLowPorts, err = readDropinFile(filepath.Join(dir, dropinLowPortsName))
	return st, err
}

func readDropinFile(path string) ([]byte, bool, error) {
	// #nosec G304 G703 -- root reads the unit's own drop-in directory.
	data, err := os.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return nil, false, nil
	case err != nil:
		return nil, false, fmt.Errorf("read %s: %w", path, err)
	case len(data) > maxDropinSize:
		return nil, false, fmt.Errorf("read %s: larger than %d bytes", path, maxDropinSize)
	}
	return data, true, nil
}

// LowPortsAction says what to do with 20-low-ports.conf.
type LowPortsAction int

// The actions of 20-low-ports.conf.
const (
	LowPortsKeep   LowPortsAction = iota // nothing to do (file as found)
	LowPortsWrite                        // needed and missing: write LowPortsData
	LowPortsRemove                       // sandbox.low_ports: false and the file exists
)

// DropinOptions are the inputs besides agent.yaml and the files as found.
type DropinOptions struct {
	// LowPorts wants 20-low-ports.conf although the configuration does not
	// imply it (setup --low-ports, deployment add --low-ports).
	LowPorts bool
	// Prune drops entries of 10-paths.conf that agent.yaml does not explain.
	Prune bool
	// Drop names entries to drop although Prune is off: paths this very
	// operation took out of agent.yaml. Entries that are still derived stay.
	Drop []string
}

// DropinPlan is the result of RenderDropins.
type DropinPlan struct {
	// Paths is the content of 10-paths.conf; it equals the file as found
	// when PathsChanged is false.
	Paths        []byte
	PathsChanged bool
	// Added and Removed are the entries this plan puts into or takes out of
	// the file; Kept are the entries found that agent.yaml does not explain.
	Added, Removed, Kept []string

	LowPorts     LowPortsAction
	LowPortsData []byte
	// Notes are one-line remarks for the operator.
	Notes []string
}

// InSync reports whether the files on disk already match the configuration.
func (p *DropinPlan) InSync() bool {
	return !p.PathsChanged && p.LowPorts == LowPortsKeep
}

// RenderDropins derives both drop-ins. lowPortData is the packaged
// 20-low-ports.conf. It reads nothing from disk and writes nothing.
func RenderDropins(cfg *Config, existing DropinState, lowPortData []byte, opts DropinOptions) (*DropinPlan, error) {
	derived, err := derivedReadWritePaths(cfg)
	if err != nil {
		return nil, err
	}
	plan := &DropinPlan{}
	drop := map[string]bool{}
	for _, d := range opts.Drop {
		if n := normUnitPath(d); !slices.ContainsFunc(derived, func(t string) bool { return normUnitPath(t) == n }) {
			drop[n] = true
		}
	}
	merged := mergeReadWritePaths(string(existing.Paths), existing.HavePaths, derived, opts.Prune, drop)
	plan.Paths = []byte(merged.text)
	plan.PathsChanged = !existing.HavePaths || !bytes.Equal(plan.Paths, existing.Paths)
	plan.Added, plan.Removed, plan.Kept = merged.added, merged.removed, merged.kept

	want := lowPortsWanted(cfg, opts.LowPorts)
	switch {
	case want == lowPortsNo && opts.LowPorts:
		return nil, errors.New("--low-ports conflicts with sandbox.low_ports: false in agent.yaml – change one of them")
	case want == lowPortsNo:
		if existing.HaveLowPorts {
			plan.LowPorts = LowPortsRemove
		}
	case want == lowPortsYes && !existing.HaveLowPorts:
		plan.LowPorts, plan.LowPortsData = LowPortsWrite, lowPortData
	case want == lowPortsYes && !bytes.Equal(existing.LowPorts, lowPortData):
		plan.Notes = append(plan.Notes, dropinLowPortsName+" differs from the packaged file; left as found")
	}
	return plan, nil
}

type lowPortsWish int

const (
	lowPortsDontCare lowPortsWish = iota
	lowPortsYes
	lowPortsNo
)

// lowPortsWanted: an explicit sandbox.low_ports wins, then any standalone
// challenge (enrollment or deployment) or the flag; otherwise no opinion.
func lowPortsWanted(cfg *Config, flag bool) lowPortsWish {
	if cfg.Sandbox.LowPorts != nil {
		if *cfg.Sandbox.LowPorts {
			return lowPortsYes
		}
		return lowPortsNo
	}
	if flag || cfg.Enrollment.Challenge == ChallengeStandalone {
		return lowPortsYes
	}
	for _, d := range cfg.Deployments {
		if d.Challenge == ChallengeStandalone {
			return lowPortsYes
		}
	}
	return lowPortsDontCare
}

// derivedReadWritePaths is state_dir, paths and sandbox.write, once each.
func derivedReadWritePaths(cfg *Config) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	add := func(field, p string) error {
		p = filepath.Clean(p)
		if !unitPathSafe(p) {
			return fmt.Errorf("%s: %q: %s", field, p, errUnitPath)
		}
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
		return nil
	}
	if err := add("state_dir", cfg.StateDir); err != nil {
		return nil, err
	}
	for _, p := range cfg.Paths {
		if err := add("paths", p); err != nil {
			return nil, err
		}
	}
	for _, p := range cfg.Sandbox.Write {
		if err := add("sandbox.write", p); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// unitPathSafe: a path that survives being one word of ReadWritePaths= (no
// split into two entries, no specifier expansion, no quoting).
func unitPathSafe(p string) bool {
	for _, r := range p {
		if unicode.IsSpace(r) || unicode.IsControl(r) || r == '%' || r == '"' || r == '\'' || (r == '\\' && filepath.Separator == '/') {
			return false
		}
	}
	return p != ""
}

// normUnitPath compares ReadWritePaths= words: the "-" prefix only means
// "ignore if missing", and trailing slashes do not matter.
func normUnitPath(t string) string {
	t = strings.TrimPrefix(t, "-")
	if t == "" {
		return t
	}
	return filepath.Clean(t)
}

type mergeResult struct {
	text                 string
	added, removed, kept []string
}

// unitLine is one logical line of a drop-in (continuation lines joined).
type unitLine struct {
	first, last int
	section     string
	rwp         bool
	tokens      []string
}

func parseUnit(lines []string) []unitLine {
	var out []unitLine
	section := ""
	for i := 0; i < len(lines); i++ {
		start := i
		joined := strings.TrimRight(lines[i], "\r")
		for strings.HasSuffix(joined, `\`) && i+1 < len(lines) {
			i++
			joined = strings.TrimSuffix(joined, `\`) + " " + strings.TrimRight(lines[i], "\r")
		}
		line := unitLine{first: start, last: i}
		t := strings.TrimSpace(joined)
		switch {
		case t == "" || t[0] == '#' || t[0] == ';':
		case t[0] == '[' && strings.HasSuffix(t, "]"):
			section = t[1 : len(t)-1]
		case section == "Service":
			if name, value, ok := strings.Cut(t, "="); ok && strings.TrimSpace(name) == "ReadWritePaths" {
				line.rwp, line.tokens = true, strings.Fields(value)
			}
		}
		line.section = section
		out = append(out, line)
	}
	return out
}

// mergeReadWritePaths applies the rule of the file's header comment to the
// text of 10-paths.conf. Nothing to do returns the text byte for byte.
func mergeReadWritePaths(existing string, have bool, derived []string, prune bool, drop map[string]bool) mergeResult {
	if !have {
		return mergeResult{text: dropinHeader + "[Service]\nReadWritePaths=" + strings.Join(derived, " ") + "\n", added: derived}
	}
	lines := strings.Split(strings.TrimSuffix(existing, "\n"), "\n")
	logical := parseUnit(lines)

	// An empty "ReadWritePaths=" resets the list: only what follows counts.
	reset := -1
	for i, l := range logical {
		if l.rwp && len(l.tokens) == 0 {
			reset = i
		}
	}
	explained := map[string]bool{}
	for _, t := range derived {
		explained[normUnitPath(t)] = true
	}
	var res mergeResult
	remove := map[string]bool{}
	present := map[string]bool{}
	for i, l := range logical {
		if !l.rwp || i <= reset {
			continue
		}
		for _, t := range l.tokens {
			n := normUnitPath(t)
			switch {
			case explained[n]:
				present[n] = true
			case drop[n] || prune:
				remove[n] = true
			default:
				if !slices.Contains(res.kept, t) {
					res.kept = append(res.kept, t)
				}
			}
		}
	}

	out := make([]string, 0, len(lines)+2)
	lastRWP, serviceEnd := -1, -1 // indexes into out
	for i, l := range logical {
		keep := lines[l.first : l.last+1]
		if l.rwp && i > reset && len(l.tokens) > 0 {
			var left []string
			for _, t := range l.tokens {
				if remove[normUnitPath(t)] {
					res.removed = append(res.removed, t)
					continue
				}
				left = append(left, t)
			}
			switch {
			case len(left) == len(l.tokens):
			case len(left) == 0:
				continue
			default:
				indent := lines[l.first][:len(lines[l.first])-len(strings.TrimLeft(lines[l.first], " \t"))]
				keep = []string{indent + "ReadWritePaths=" + strings.Join(left, " ")}
			}
			out = append(out, keep...)
			if len(keep) == 1 {
				lastRWP = len(out) - 1
			} else {
				lastRWP = -1
			}
			serviceEnd = len(out)
			continue
		}
		out = append(out, keep...)
		if l.section == "Service" && strings.TrimSpace(strings.Join(keep, "")) != "" {
			serviceEnd = len(out)
		}
	}

	for _, t := range derived {
		if !present[normUnitPath(t)] {
			res.added = append(res.added, t)
		}
	}
	switch {
	case len(res.added) == 0:
	case lastRWP >= 0:
		out[lastRWP] = strings.TrimRight(out[lastRWP], " \t") + " " + strings.Join(res.added, " ")
	case serviceEnd >= 0:
		out = slices.Insert(out, serviceEnd, "ReadWritePaths="+strings.Join(res.added, " "))
	default:
		if len(out) > 0 && strings.TrimSpace(out[len(out)-1]) != "" {
			out = append(out, "")
		}
		out = append(out, "[Service]", "ReadWritePaths="+strings.Join(res.added, " "))
	}
	if len(res.added) == 0 && len(res.removed) == 0 {
		res.text = existing
		return res
	}
	res.text = strings.Join(out, "\n") + "\n"
	return res
}

// writeDropins applies a plan: atomically, mode 0644, parent directory 0755.
// An unchanged 10-paths.conf is rewritten with itself, which only sets the mode.
func writeDropins(dir string, plan *DropinPlan) error {
	// #nosec G301 G703 -- root chooses the standard systemd drop-in directory.
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create unit drop-in directory: %w", err)
	}
	if err := atomicSetupFile(filepath.Join(dir, dropinPathsName), plan.Paths, 0o644); err != nil {
		return err
	}
	lowPorts := filepath.Join(dir, dropinLowPortsName)
	switch plan.LowPorts {
	case LowPortsWrite:
		return atomicSetupFile(lowPorts, plan.LowPortsData, 0o644)
	case LowPortsRemove:
		// #nosec G703 -- fixed file name in the unit's drop-in directory.
		if err := os.Remove(lowPorts); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove %s: %w", dropinLowPortsName, err)
		}
	case LowPortsKeep:
	}
	return nil
}

// reportDropins tells the operator what happened to a drop-in that existed.
func reportDropins(w io.Writer, plan *DropinPlan, hadPaths bool) {
	if hadPaths && len(plan.Added) > 0 {
		_, _ = fmt.Fprintf(w, "Added to %s: %s\n", dropinPathsName, strings.Join(plan.Added, " "))
	}
	if len(plan.Removed) > 0 {
		_, _ = fmt.Fprintf(w, "Removed from %s: %s\n", dropinPathsName, strings.Join(plan.Removed, " "))
	}
	if len(plan.Kept) > 0 {
		_, _ = fmt.Fprintf(w, "Kept in %s (agent.yaml does not explain them): %s\n  Record them under sandbox.write in agent.yaml to make them part of the configuration.\n", dropinPathsName, strings.Join(plan.Kept, " "))
	}
	if plan.LowPorts == LowPortsRemove {
		_, _ = fmt.Fprintf(w, "Removed %s (sandbox.low_ports: false).\n", dropinLowPortsName)
	}
	for _, n := range plan.Notes {
		_, _ = fmt.Fprintln(w, n)
	}
}

// DescribeDropins is the sandbox paragraph of "config check": what the
// configuration implies and whether the drop-ins in dir already match it. A
// host without the unit (a laptop) is not an error.
func DescribeDropins(cfg *Config, dir string) (string, error) {
	derived, err := derivedReadWritePaths(cfg)
	if err != nil {
		return "", err
	}
	state, err := ReadDropins(dir)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "  sandbox       ReadWritePaths %s\n", strings.Join(derived, " "))
	lowPorts := "left as found"
	switch lowPortsWanted(cfg, false) {
	case lowPortsYes:
		lowPorts = "written"
	case lowPortsNo:
		lowPorts = "removed (sandbox.low_ports: false)"
	case lowPortsDontCare:
	}
	fmt.Fprintf(&b, "                %s %s\n", dropinLowPortsName, lowPorts)
	if !state.HavePaths {
		fmt.Fprintf(&b, "  drop-ins      not installed in %s (setup writes them)\n", dir)
		return b.String(), nil
	}
	plan, err := RenderDropins(cfg, state, nil, DropinOptions{})
	if err != nil {
		return "", err
	}
	switch {
	case plan.LowPorts == LowPortsWrite:
		fmt.Fprintf(&b, "  drop-ins      differ: %s is missing – run \"myownpki-agent sandbox sync\"\n", dropinLowPortsName)
	case plan.LowPorts == LowPortsRemove:
		fmt.Fprintf(&b, "  drop-ins      differ: %s exists – run \"myownpki-agent sandbox sync\"\n", dropinLowPortsName)
	case len(plan.Added) > 0:
		fmt.Fprintf(&b, "  drop-ins      differ: %s lacks %s – run \"myownpki-agent sandbox sync\"\n", dropinPathsName, strings.Join(plan.Added, " "))
	default:
		fmt.Fprintf(&b, "  drop-ins      match agent.yaml\n")
	}
	if len(plan.Kept) > 0 {
		fmt.Fprintf(&b, "                %s also holds entries agent.yaml does not explain: %s\n", dropinPathsName, strings.Join(plan.Kept, " "))
	}
	return b.String(), nil
}
