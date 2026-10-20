package legacy

import (
	"bufio"
	"bytes"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// index.txt is the database of `openssl ca`: one line per certificate the
// CA signed, tab-separated:
//
//	status  expiry  revocation  serial  file  subject
//
// status V (valid), R (revoked) or E (expired, after -updatedb); the dates
// are UTCTime (YYMMDDHHMMSSZ) or GeneralizedTime (YYYYMMDDHHMMSSZ). The
// revocation field is "time[,reason[,extra]]": -crl_reason writes
// "time,reason", -crl_hold "time,holdInstruction,OID", -crl_compromise
// "time,keyTime,TIME" and -crl_CA_compromise "time,CAkeyTime,TIME".

// Entry is one line of index.txt.
type Entry struct {
	Line    int
	Status  string // V, R or E
	Expiry  time.Time
	Serial  string // upper-case hex, even length (like ca.SerialHex)
	File    string // the serial as written: newcerts/<File>.pem
	Subject string
	// Revoked is set for status R.
	Revoked *Revocation
}

// Revocation as pki.sh recorded it.
type Revocation struct {
	Time time.Time
	// Reason is the OpenSSL name: unspecified, keyCompromise, CACompromise,
	// affiliationChanged, superseded, cessationOfOperation, certificateHold,
	// removeFromCRL; "" when the line names none.
	Reason string
	// Invalidity is the compromise time of keyTime/CAkeyTime.
	Invalidity *time.Time
}

var opensslReasons = map[string]bool{
	"unspecified": true, "keyCompromise": true, "CACompromise": true, "affiliationChanged": true,
	"superseded": true, "cessationOfOperation": true, "certificateHold": true, "removeFromCRL": true,
}

func parseIndex(data []byte) ([]Entry, []string) {
	var out []Entry
	var problems []string
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64<<10), 64<<10)
	n := 0
	for sc.Scan() {
		n++
		line := strings.TrimSuffix(sc.Text(), "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		e, err := parseIndexLine(line)
		if err != nil {
			problems = append(problems, fmt.Sprintf("line %d: %v", n, err))
			continue
		}
		e.Line = n
		out = append(out, e)
	}
	if err := sc.Err(); err != nil {
		problems = append(problems, "not read to the end: "+err.Error())
	}
	return out, problems
}

func parseIndexLine(line string) (Entry, error) {
	f := strings.Split(line, "\t")
	if len(f) != 6 {
		return Entry{}, fmt.Errorf("%d fields instead of 6", len(f))
	}
	e := Entry{Status: f[0], File: f[3], Subject: f[5]}
	var err error
	if e.Expiry, err = opensslTime(f[1]); err != nil {
		return Entry{}, fmt.Errorf("expiry: %w", err)
	}
	n, ok := new(big.Int).SetString(f[3], 16)
	if f[3] == "" || !ok || n.Sign() <= 0 || strings.ContainsAny(f[3], "+-xX/.") {
		return Entry{}, fmt.Errorf("serial %q is not hex", clip(f[3], 70))
	}
	e.Serial = serialHex(n)
	switch e.Status {
	case "V", "E":
		if f[2] != "" {
			return Entry{}, fmt.Errorf("status %s with a revocation date", e.Status)
		}
	case "R":
		if e.Revoked, err = parseRevocation(f[2]); err != nil {
			return Entry{}, err
		}
	default:
		return Entry{}, fmt.Errorf("unknown status %q", clip(e.Status, 10))
	}
	return e, nil
}

func parseRevocation(s string) (*Revocation, error) {
	parts := strings.Split(s, ",")
	t, err := opensslTime(parts[0])
	if err != nil {
		return nil, fmt.Errorf("revocation time: %w", err)
	}
	r := &Revocation{Time: t}
	if len(parts) == 1 {
		return r, nil
	}
	switch parts[1] {
	case "keyTime", "CAkeyTime":
		r.Reason = "keyCompromise"
		if parts[1] == "CAkeyTime" {
			r.Reason = "CACompromise"
		}
		if len(parts) != 3 {
			return nil, fmt.Errorf("%s without its time", parts[1])
		}
		inv, ierr := opensslTime(parts[2])
		if ierr != nil {
			return nil, fmt.Errorf("compromise time: %w", ierr)
		}
		r.Invalidity = &inv
	case "holdInstruction":
		r.Reason = "certificateHold"
	default:
		if !opensslReasons[parts[1]] || len(parts) > 2 {
			return nil, fmt.Errorf("unknown revocation reason %q", clip(strings.Join(parts[1:], ","), 40))
		}
		r.Reason = parts[1]
	}
	return r, nil
}

// opensslTime reads ASN.1 UTCTime or GeneralizedTime as index.txt has them.
func opensslTime(s string) (time.Time, error) {
	var layout string
	switch len(s) {
	case 13:
		layout = "060102150405Z"
	case 15:
		layout = "20060102150405Z"
	default:
		return time.Time{}, fmt.Errorf("%q is not an OpenSSL time", clip(s, 20))
	}
	t, err := time.Parse(layout, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("%q is not an OpenSSL time", clip(s, 20))
	}
	// UTCTime: 50–99 are 1950–1999 (RFC 5280 §4.1.2.5.1); Go reads 69–99 so.
	if len(s) == 13 && t.Year() >= 2050 {
		t = t.AddDate(-100, 0, 0)
	}
	return t.UTC(), nil
}
