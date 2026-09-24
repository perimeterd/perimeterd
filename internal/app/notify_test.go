package app

import (
	"fmt"
	"strings"
	"testing"
	"testing/synctest"
	"time"
)

func TestStartupExtensionsRespectOverallDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		deadline := time.Now().Add(75 * time.Minute)
		messages := make(chan string, 256)
		notifier := newStartupNotifier(func(message string) error {
			messages <- message
			return nil
		}, deadline)
		t.Cleanup(func() { _ = notifier.Stop() })
		for remaining := 75 * time.Minute; remaining > 0; remaining -= 20 * time.Second {
			synctest.Wait()
			if len(messages) != 1 {
				t.Fatalf("remaining %s: received %d extensions, want one", remaining, len(messages))
			}
			var extension int64
			if _, err := fmt.Sscanf(<-messages, "EXTEND_TIMEOUT_USEC=%d", &extension); err != nil {
				t.Fatalf("parse extension: %v", err)
			}
			want := min(remaining, 60*time.Second).Microseconds()
			if extension != want {
				t.Fatalf("remaining %s: extension = %d, want %d microseconds", remaining, extension, want)
			}
			time.Sleep(20 * time.Second)
		}
		synctest.Wait()
		if len(messages) != 0 {
			t.Fatalf("expired startup emitted %d extensions", len(messages))
		}
		if err := notifier.Stop(); err != nil {
			t.Fatal(err)
		}
		time.Sleep(time.Minute)
		if len(messages) != 0 {
			t.Fatalf("stopped notifier emitted %d extensions", len(messages))
		}
	})
}

func TestStartupExtensionRoundsDownToDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var message string
		notifier := newStartupNotifier(func(value string) error {
			message = value
			return nil
		}, time.Now().Add(time.Second+999*time.Nanosecond))
		t.Cleanup(func() { _ = notifier.Stop() })
		synctest.Wait()
		if !strings.HasPrefix(message, "EXTEND_TIMEOUT_USEC=1000000\n") {
			t.Fatalf("extension rounds past overall deadline: %q", message)
		}
		if err := notifier.Stop(); err != nil {
			t.Fatal(err)
		}
	})
}
