// Package notify sends desktop notifications.
package notify

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// Urgency maps to notify-send's --urgency.
type Urgency string

const (
	Normal   Urgency = "normal"
	Critical Urgency = "critical"
)

// Send shows a desktop notification. Only Linux (notify-send, i.e. any
// freedesktop notification daemon) is supported.
func Send(ctx context.Context, title, body string, urgency Urgency) error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("desktop notifications are not supported on %s", runtime.GOOS)
	}
	bin, err := exec.LookPath("notify-send")
	if err != nil {
		return errors.New("notify-send not found; install libnotify")
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, bin, "--app-name=nugetwatch", "--urgency="+string(urgency), title, body).CombinedOutput()
	if err != nil {
		if msg := strings.TrimSpace(string(out)); msg != "" {
			return fmt.Errorf("notify-send: %w: %s", err, msg)
		}
		return fmt.Errorf("notify-send: %w", err)
	}
	return nil
}
