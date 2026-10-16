// Blocked-prompt notifier: the bell and OSC 9 alert raised while a permission prompt
// holds the run.
package tui

import (
	"context"
	"io"
	"os"
	"time"

	"golang.org/x/term"
)

const (
	// Nothing from the prompt request may be added to promptNotifyText: the payload lands
	// in desktop-notification history and on lock screens, where a subject, command, or
	// path has no business being.
	promptNotifyText   = "Codemeld is waiting on your input"
	promptNotifyDelay  = 30 * time.Second
	promptNotifyRepeat = 60 * time.Second
)

func PromptNotifySequence() string {
	return "\x1b]9;" + promptNotifyText + "\x07"
}

func PromptNotifyTTY(w io.Writer) bool {
	f, ok := w.(*os.File)
	return ok && term.IsTerminal(int(f.Fd()))
}

type PromptNotifier struct {
	stop chan struct{}
	done chan struct{}
}

func StartPromptNotifier(ctx context.Context, after func(time.Duration) <-chan time.Time, notify func()) *PromptNotifier {
	n := &PromptNotifier{stop: make(chan struct{}), done: make(chan struct{})}
	go func() {
		defer close(n.done)
		for d := promptNotifyDelay; ; d = promptNotifyRepeat {
			select {
			case <-n.stop:
				return
			case <-ctx.Done():
				return
			case <-after(d):
			}
			// A tick that becomes ready together with a stop must resolve as a stop, so a
			// prompt answered on the tick boundary stays silent.
			select {
			case <-n.stop:
				return
			case <-ctx.Done():
				return
			default:
			}
			notify()
		}
	}()
	return n
}

// Stop waits for an in-flight notify to return, so no write lands after the prompt it
// belongs to is gone.
func (n *PromptNotifier) Stop() {
	close(n.stop)
	<-n.done
}

// notifyPromptWaiting rings the bell and emits the sequence on the tview event-loop
// goroutine, which owns the terminal. Outside the running window the tick is dropped:
// QueueUpdate blocks until the loop executes it, and there is no loop to do so.
func (a *App) notifyPromptWaiting() {
	if a.stopping.Load() || !a.running.Load() {
		return
	}
	a.app.QueueUpdate(func() {
		if a.stopping.Load() {
			return
		}
		a.beep()
		a.promptNotifyWrite(PromptNotifySequence())
	})
}

func defaultPromptNotifyWrite(seq string) {
	if !PromptNotifyTTY(os.Stdout) {
		return
	}
	_, _ = io.WriteString(os.Stdout, seq)
}
