package guides

import (
	"embed"
	"fmt"
	"io/fs"
	"slices"
	"strings"
	"sync"
)

// content holds the guides of the product: one Markdown file per guide. To add
// a guide, add a file here; nothing else changes (at most MaxGuides).
//
//go:embed content/*.md
var content embed.FS

// Registry is the set of guides of one instance. It is built once and read-only.
type Registry struct {
	list   []*Guide
	bySlug map[string]*Guide
}

// NewRegistry parses every *.md file of dir in fsys. The file name without the
// extension is the slug. A file that is not a guide, more than MaxGuides files,
// a guide that does not parse and a link to a guide that does not exist are
// errors, so a mistake stops the build and the start, not a reader.
func NewRegistry(fsys fs.FS, dir string) (*Registry, error) {
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return nil, fmt.Errorf("guides: read %s: %w", dir, err)
	}
	r := &Registry{bySlug: map[string]*Guide{}}
	for _, e := range entries {
		slug, ok := strings.CutSuffix(e.Name(), ".md")
		if e.IsDir() || !ok {
			return nil, fmt.Errorf("guides: %s is not a guide file (only <slug>.md files belong in %s)", e.Name(), dir)
		}
		src, err := fs.ReadFile(fsys, dir+"/"+e.Name())
		if err != nil {
			return nil, fmt.Errorf("guides: read %s: %w", e.Name(), err)
		}
		g, err := Parse(slug, src)
		if err != nil {
			return nil, err
		}
		r.list = append(r.list, g)
		r.bySlug[slug] = g
	}
	if len(r.list) > MaxGuides {
		return nil, fmt.Errorf("guides: %d guides, at most %d are allowed", len(r.list), MaxGuides)
	}
	slices.SortFunc(r.list, func(a, b *Guide) int {
		if a.Order != b.Order {
			return a.Order - b.Order
		}
		return strings.Compare(a.Slug, b.Slug)
	})
	for _, g := range r.list {
		for _, l := range g.Links() {
			if l.Target != LinkGuide {
				continue
			}
			target, _, _ := strings.Cut(strings.TrimPrefix(l.Href, "/guides/"), "#")
			if _, ok := r.bySlug[target]; !ok {
				return nil, fmt.Errorf("guides: %s links to the guide %q, which does not exist", g.Slug, target)
			}
		}
	}
	return r, nil
}

var (
	embeddedOnce sync.Once
	embedded     *Registry
	errEmbedded  error
)

// Embedded is the registry of the guides compiled into the binary.
func Embedded() (*Registry, error) {
	embeddedOnce.Do(func() { embedded, errEmbedded = NewRegistry(content, "content") })
	return embedded, errEmbedded
}

// Empty is a registry without guides.
func Empty() *Registry { return &Registry{bySlug: map[string]*Guide{}} }

// List returns the guides in reading order (Order, then slug). The caller may
// keep the slice but must not change the guides.
func (r *Registry) List() []*Guide { return slices.Clone(r.list) }

// Get returns the guide with this slug. A slug outside a-z, 0-9 and - is never
// looked up.
func (r *Registry) Get(slug string) (*Guide, bool) {
	if !ValidSlug(slug) {
		return nil, false
	}
	g, ok := r.bySlug[slug]
	return g, ok
}
