package clitoken

import (
	"context"
	"fmt"
	"os/exec"
	"runtime"
)

type Opener interface {
	// Open opens the provided URL in the user's browser
	Open(ctx context.Context, url string) error
}

// DetectOpener attempts to find the best opener for a user's system. If there
// is no best opener for the system, it defaults to an opener that prints the
// URL to the console so the user can click on it.
func DetectOpener() Opener {
	switch runtime.GOOS {
	case "darwin":
		if path, err := exec.LookPath("open"); err == nil {
			return &CommandOpener{CommandName: path}
		}
	case "linux":
		if path, err := exec.LookPath("xdg-open"); err == nil {
			return &CommandOpener{CommandName: path}
		}
	}
	return &EchoOpener{}
}

// CommandOpener opens a URL by executing a command with the URL as the first
// argument. CommandOpener works well with MacOS's `open` command.
type CommandOpener struct {
	CommandName string
}

func (o *CommandOpener) Open(ctx context.Context, url string) error {
	return exec.CommandContext(ctx, o.CommandName, url).Run()
}

// EchoOpener opens a URL by printing it to the console for the user to
// manually click on. It is used as a last resort.
type EchoOpener struct{}

func (o *EchoOpener) Open(ctx context.Context, url string) error {
	_, err := fmt.Printf("To continue, open this URL in a browser: %s\n", url)
	return err
}
