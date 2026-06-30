//go:build windows

package main

import (
	"os"
	"os/exec"
	"syscall"
)

const (
	windowsDetachedProcess     = 0x00000008
	windowsCreateNewProcessGrp = 0x00000200
)

func startDetached(args []string, logPath string) error {
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer logFile.Close()

	cmd := exec.Command(os.Args[0], args...)
	cmd.Env = append(os.Environ(), "TARION_BACKGROUND_CHILD=1")
	cmd.Stdin = nil
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windowsDetachedProcess | windowsCreateNewProcessGrp}
	return cmd.Start()
}
