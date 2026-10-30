package nodeops

import (
	"context"
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

type serviceOperationKey struct{}
type serviceOperation struct {
	root string
	file *os.File
}

// One lock covers backup, activation and restore. Mutating child commands
// inherit its open file description, so a parent exit cannot release the lock
// while its service-management client is still executing.
func acquireServiceOperation(ctx context.Context, root string) (context.Context, func(), error) {
	if err := ctx.Err(); err != nil {
		return ctx, nil, err
	}
	if held, ok := ctx.Value(serviceOperationKey{}).(serviceOperation); ok {
		if held.root != root || held.file == nil {
			return ctx, nil, errors.New("service-operation-scope-mismatch")
		}
		if _, err := held.file.Stat(); err != nil {
			return ctx, nil, errors.New("service-operation-lock-lost")
		}
		return ctx, func() {}, nil
	}
	if err := privateDirectoryTree(root); err != nil {
		return ctx, nil, err
	}
	path := filepath.Join(root, "service-operation.lock")
	if err := privateFile(path, true); err != nil {
		return ctx, nil, err
	}
	fd, err := unix.Open(path, unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return ctx, nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		file.Close()
		return ctx, nil, errors.New("service-operation-busy")
	}
	if err := privateFile(path, false); err != nil {
		file.Close()
		return ctx, nil, err
	}
	return context.WithValue(ctx, serviceOperationKey{}, serviceOperation{root, file}), func() { file.Close() }, nil
}
func serviceMutation(program string, args []string) bool {
	if program == "systemctl" && len(args) > 0 {
		switch args[0] {
		case "enable", "disable", "start", "stop", "daemon-reload":
			return true
		}
	}
	if program == "docker" && len(args) > 2 && args[0] == "--host" && args[1] == "unix:///var/run/docker.sock" {
		switch args[2] {
		case "start", "stop", "update", "rename", "compose":
			return true
		}
	}
	return false
}
