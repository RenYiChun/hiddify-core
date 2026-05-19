package hutils

import (
	"fmt"
	"net"
	"os"
	"runtime/debug"
)

func IsPortInUse(port uint16) bool {
	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return true
	}
	defer listener.Close()
	return false
}

func redirectStderr(path string) error {
	outputFile, err := os.Create(path)
	if err != nil {
		return err
	}
	defer outputFile.Close()
	return debug.SetCrashOutput(outputFile, debug.CrashOptions{})
}
