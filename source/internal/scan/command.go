package scan

import (
	"bytes"
	"context"
	"time"
)

func runCommand(timeout time.Duration, name string, args ...string) (stdout []byte, stderr []byte, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := commandContext(ctx, name, args...)
	var out bytes.Buffer
	var errOut bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errOut
	err = cmd.Run()
	return normalizeTextOutput(out.Bytes()), normalizeTextOutput(errOut.Bytes()), err
}
