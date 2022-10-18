package util

import (
	"syscall"

	"github.com/google/syzkaller/pkg/log"
)

// gracefully terminate the whole program and report error,
// ONLY use after SIGINT handler is registered !!!
func GFatalf(msg string, args ...interface{}) {
	log.Logf(0, "[FATAL] "+msg, args...)
	syscall.Kill(syscall.Getpid(), syscall.SIGINT)
	select {}
}
