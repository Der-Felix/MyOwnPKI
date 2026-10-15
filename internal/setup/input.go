package setup

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
)

// maxLine bounds one line of standard input (passphrase or password).
const maxLine = 1024

// LineInput is the UI of init --stdin: every secret is the next line of
// standard input. Only the line end (\n or \r\n) is removed – spaces belong
// to the secret, also at its end (owner 2026-10-15).
type LineInput struct {
	in  *bufio.Reader
	out io.Writer
}

// NewLineInput reads secrets from in and writes messages to out.
func NewLineInput(in io.Reader, out io.Writer) *LineInput {
	return &LineInput{in: bufio.NewReaderSize(in, maxLine+2), out: out}
}

// Printf writes a message.
func (l *LineInput) Printf(format string, args ...any) { _, _ = fmt.Fprintf(l.out, format, args...) }

// ReadLine is not used with --stdin: every answer comes from a flag.
func (l *LineInput) ReadLine(prompt string) (string, error) {
	return "", fmt.Errorf("init --stdin can't ask %q – give it as a flag", prompt)
}

// ReadSecret returns the next line without its line end.
func (l *LineInput) ReadSecret(string) ([]byte, error) {
	line, err := l.in.ReadSlice('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		if errors.Is(err, bufio.ErrBufferFull) {
			return nil, fmt.Errorf("a line of standard input is longer than %d bytes", maxLine)
		}
		return nil, err
	}
	if bytes.HasSuffix(line, []byte("\n")) {
		line = bytes.TrimSuffix(bytes.TrimSuffix(line, []byte("\n")), []byte("\r"))
	}
	if len(line) == 0 {
		return nil, errors.New("standard input ended early: init --stdin wants the unseal passphrase on the first line and the admin password on the second")
	}
	if len(line) > maxLine {
		return nil, fmt.Errorf("a line of standard input is longer than %d bytes", maxLine)
	}
	return bytes.Clone(line), nil
}
