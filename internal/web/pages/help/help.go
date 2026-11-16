// Package help holds the pages of the Help area: the guides and First steps.
package help

import "github.com/Der-Felix/MyOwnPKI/internal/guides"

// section is the blocks below one level 2 heading; the blocks before the first
// heading form a section without one.
type section struct {
	Heading *guides.Block
	Blocks  []guides.Block
}

func sections(blocks []guides.Block) []section {
	var out []section
	for i := range blocks {
		b := blocks[i]
		if b.Kind == guides.KindHeading && b.Level == 2 {
			out = append(out, section{Heading: &blocks[i]})
			continue
		}
		if len(out) == 0 {
			out = append(out, section{})
		}
		out[len(out)-1].Blocks = append(out[len(out)-1].Blocks, b)
	}
	return out
}

// LinkHref is the href of a link: an anchor gets the prefix of the heading ids.
func LinkHref(in guides.Inline) string {
	if in.Target == guides.LinkAnchor {
		return "#" + AnchorID(in.Href)
	}
	return in.Href
}

// CodeLabel names a code block for assistive technology.
func CodeLabel(lang string) string {
	switch lang {
	case "bash":
		return "Shell commands"
	case "powershell":
		return "PowerShell commands"
	case "yaml":
		return "YAML"
	case "json":
		return "JSON"
	case "ini":
		return "Configuration file"
	default:
		return "Text"
	}
}
