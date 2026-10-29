package web

import (
	"strconv"

	"github.com/Der-Felix/MyOwnPKI/internal/monitor"
	"github.com/Der-Felix/MyOwnPKI/internal/web/components"
	"github.com/Der-Felix/MyOwnPKI/internal/web/view"
)

// alertNumber is the dashboard figure of the open alerts: red with a
// critical one, amber with warnings only.
func alertNumber(open []monitor.Alert) components.Number {
	status := view.Status("")
	for _, a := range open {
		if a.Severity == monitor.Critical {
			status = view.StatusCrit
			break
		}
		status = view.StatusWarn
	}
	return components.Number{Label: "Open alerts", Value: strconv.Itoa(len(open)), Status: status}
}

// alertMessages are the alerts the dashboard doesn't find on its own: CRLs,
// CA certificates and agent certificates it checks itself (without the
// minute delay of the monitoring), so they would show twice.
func alertMessages(open []monitor.Alert) []view.Message {
	var out []view.Message
	for _, a := range open {
		switch a.Kind {
		case monitor.KindAgentSilent, monitor.KindDeployFailed:
		case monitor.KindCertExpiry:
			if a.Severity != monitor.Critical {
				continue // warnings are in "Expiring in the next 30 days"
			}
		default:
			continue
		}
		kind := view.MessageWarning
		if a.Severity == monitor.Critical {
			kind = view.MessageError
		}
		out = append(out, view.Message{Kind: kind, Text: a.Detail, Href: a.Href, LinkText: "Open"})
	}
	return out
}
