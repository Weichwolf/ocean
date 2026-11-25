package lab

import (
	"context"

	"github.com/Weichwolf/ocean/internal/qemu"
)

func qmp(path, name, command string) error {
	return qemu.Call(context.Background(), path, name, command, nil)
}
