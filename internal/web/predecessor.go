package web

import (
	"strconv"

	"github.com/Der-Felix/MyOwnPKI/internal/predecessor"
	"github.com/Der-Felix/MyOwnPKI/internal/web/pages/admin"
)

func predecessorOptions(selected predecessor.Policy) []admin.Option {
	return []admin.Option{
		{Value: predecessor.Now, Label: "Revoke now (after the replacement is confirmed)", Selected: selected.Choice == predecessor.Now},
		{Value: predecessor.After, Label: "Revoke after N days", Selected: selected.Choice == predecessor.After},
		{Value: predecessor.Never, Label: "Never revoke", Selected: selected.Choice == predecessor.Never},
	}
}

func predecessorFields(choiceID, daysID string, selected predecessor.Policy) []admin.Field {
	days := selected.Days
	if days == 0 {
		days = 7
	}
	return []admin.Field{
		{ID: choiceID, Label: "Predecessor", Type: "select", Options: predecessorOptions(selected), Required: true},
		{ID: daysID, Label: "Days before revocation", Type: "number", Value: strconv.Itoa(days), Hint: "1 to 30; used only for Revoke after N days. Reason is always superseded."},
	}
}

func predecessorFromForm(value func(string) string, choiceID, daysID string) predecessor.Policy {
	policy := predecessor.Policy{Choice: value(choiceID)}
	if policy.Choice == predecessor.After {
		policy.Days, _ = strconv.Atoi(value(daysID))
	}
	return policy
}

func predecessorText(policy predecessor.Policy) string {
	switch policy.Choice {
	case predecessor.Now:
		return "revoke the predecessor as superseded after confirmation"
	case predecessor.After:
		return "revoke the predecessor as superseded after " + strconv.Itoa(policy.Days) + " days"
	default:
		return "never revoke the predecessor"
	}
}
