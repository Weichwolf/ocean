package qemu

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Weichwolf/ocean/internal/workload"
	"golang.org/x/sys/unix"
)

var (
	guestID               = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	tapName               = regexp.MustCompile(`^[a-z][a-z0-9-]{0,14}$`)
	errMonitorUnavailable = errors.New("the KVM process holds its writer lock while the monitor is unavailable")
)

// MAC returns a locally administered unicast address derived from a VM's
// persistent ID. Placement changes must reuse the same ID and address.
func MAC(id string) string {
	sum := sha256.Sum256([]byte(id))
	return net.HardwareAddr{(sum[0] & 0xfc) | 2, sum[1], sum[2], sum[3], sum[4], sum[5]}.String()
}

// Guest is a Server Core runtime on an enrolled Debian KVM worker. The caller
// owns the writer grant for Disk and FirmwareVars and prepares Tap before Start.
// The runtime directory must be private to the local worker account.
type Guest struct {
	ID           string
	Generation   string
	Size         string
	Directory    string
	Disk         string
	FirmwareCode string
	FirmwareVars string
	Tap          string
}

type PowerState string

const (
	PowerOff     PowerState = "stopped"
	PowerRunning PowerState = "running"
)

func (g Guest) name() string       { return "ocean-" + g.ID + "-" + g.Generation }
func (g Guest) socket() string     { return filepath.Join(g.Directory, "qmp") }
func (g Guest) writerLock() string { return filepath.Join(g.Directory, "writer.lock") }

func (g Guest) validate() error {
	if !guestID.MatchString(g.ID) || !guestID.MatchString(g.Generation) || !absolutePath(g.Directory) || len(g.socket()) > 107 {
		return errors.New("invalid KVM guest identity or runtime directory")
	}
	return nil
}

func absolutePath(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && path != "/" && !strings.ContainsRune(path, 0)
}

func (g Guest) withLock(operation func() error) error {
	if err := g.validate(); err != nil {
		return err
	}
	if err := os.MkdirAll(g.Directory, 0700); err != nil {
		return err
	}
	var stat unix.Stat_t
	if err := unix.Lstat(g.Directory, &stat); err != nil {
		return err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Mode&0077 != 0 || stat.Uid != uint32(os.Geteuid()) {
		return errors.New("the KVM runtime directory must be private and owned by the worker")
	}
	lock, err := os.OpenFile(filepath.Join(g.Directory, "lock"), os.O_CREATE|os.O_RDWR|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0600)
	if err != nil {
		return err
	}
	defer func() { _ = lock.Close() }()
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return fmt.Errorf("lock KVM guest runtime: %w", err)
	}
	return operation()
}

func (g Guest) Status(ctx context.Context) (state PowerState, err error) {
	err = g.withLock(func() error {
		state, err = g.status(ctx)
		return err
	})
	return state, err
}

func (g Guest) status(ctx context.Context) (PowerState, error) {
	var result struct {
		Status PowerState `json:"status"`
	}
	err := Call(ctx, g.socket(), g.name(), "query-status", &result)
	if err != nil && !errors.Is(err, os.ErrNotExist) && !errors.Is(err, unix.ECONNREFUSED) {
		return "", err
	}
	active, lockErr := g.hasProcess()
	if lockErr != nil {
		return "", lockErr
	}
	if err == nil {
		if !active || result.Status == "" {
			return "", errors.New("the KVM monitor is missing a writer lock or a power state")
		}
		return result.Status, nil
	}
	if active {
		return "", errMonitorUnavailable
	}
	return PowerOff, nil
}

// The launch wrapper retains an open writer lock in QEMU, including during
// early startup and while its monitor is unavailable.
func (g Guest) hasProcess() (bool, error) {
	file, err := os.OpenFile(g.writerLock(), os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer func() { _ = file.Close() }()
	err = unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	if errors.Is(err, unix.EWOULDBLOCK) {
		return true, nil
	}
	return false, err
}

// Start starts a guest or confirms that the same generation is already running.
func (g Guest) Start(ctx context.Context) error {
	return g.withLock(func() error {
		state, err := g.status(ctx)
		if err != nil || state == PowerRunning {
			return err
		}
		if state != PowerOff {
			return fmt.Errorf("cannot start a KVM guest in state %q", state)
		}
		args, err := g.arguments()
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		launch := []string{"--nonblock", "--no-fork", g.writerLock(), "/usr/bin/nice", "-n", "10", "/usr/bin/qemu-system-x86_64"}
		command := exec.Command("/usr/bin/flock", append(launch, args...)...)
		command.Stderr = os.Stderr
		command.SysProcAttr = &unix.SysProcAttr{Setsid: true}
		if err := command.Start(); err != nil {
			return fmt.Errorf("start KVM guest: %w", err)
		}
		exited := make(chan error, 1)
		go func() { exited <- command.Wait() }()
		if err := g.waitForStart(ctx, exited); err != nil {
			killErr := command.Process.Kill()
			if errors.Is(killErr, os.ErrProcessDone) {
				killErr = nil
			}
			return errors.Join(err, killErr)
		}
		return nil
	})
}

func (g Guest) waitForStart(ctx context.Context, exited <-chan error) error {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case err := <-exited:
			if err == nil {
				return errors.New("KVM guest exited before startup completed")
			}
			return fmt.Errorf("KVM guest exited before startup completed: %w", err)
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			state, err := g.status(ctx)
			if errors.Is(err, errMonitorUnavailable) || state == PowerOff {
				continue
			}
			if err != nil || state == PowerRunning {
				return err
			}
			return fmt.Errorf("the KVM guest started in state %q", state)
		}
	}
}

// Stop completes only once the local QEMU process has lost its writer lock.
// Repeat ACPI notification to cover guests that ignore it during early boot.
func (g Guest) Stop(ctx context.Context, force bool) error {
	return g.withLock(func() error {
		state, err := g.status(ctx)
		if err != nil || state == PowerOff {
			return err
		}
		command := "system_powerdown"
		if force {
			command = "quit"
		}
		var retry <-chan time.Time
		if !force {
			button := time.NewTicker(5 * time.Second)
			defer button.Stop()
			retry = button.C
		}
		ticker := time.NewTicker(200 * time.Millisecond)
		defer ticker.Stop()
		requestErr := Call(ctx, g.socket(), g.name(), command, nil)
		for {
			active, err := g.hasProcess()
			if err != nil || !active {
				return err
			}
			if requestErr != nil {
				return requestErr
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-retry:
				requestErr = Call(ctx, g.socket(), g.name(), command, nil)
			case <-ticker.C:
			}
		}
	})
}

func (g Guest) arguments() ([]string, error) {
	size, ok := workload.VirtualMachineSize(g.Size)
	if !ok || !tapName.MatchString(g.Tap) {
		return nil, errors.New("invalid KVM hardware profile or TAP interface")
	}
	for _, path := range []string{g.Disk, g.FirmwareCode, g.FirmwareVars} {
		if !absolutePath(path) {
			return nil, errors.New("the KVM disk and firmware require absolute paths")
		}
	}
	if g.Disk == g.FirmwareVars || g.FirmwareCode == g.FirmwareVars || g.FirmwareCode == g.Disk {
		return nil, errors.New("KVM disk and firmware paths must be distinct")
	}
	path := func(path string) string { return strings.ReplaceAll(path, ",", ",,") }
	return []string{
		"-name", g.name(), "-uuid", g.ID, "-machine", "pc-q35-10.0,accel=kvm,smm=on", "-cpu", "host",
		"-m", strconv.Itoa(size.MemoryMiB), "-smp", strconv.Itoa(size.VCPUs),
		"-no-user-config", "-nodefaults", "-display", "none", "-monitor", "none", "-serial", "none",
		"-qmp", "unix:" + path(g.socket()) + ",server=on,wait=off",
		"-sandbox", "on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny",
		"-drive", "if=pflash,format=raw,readonly=on,file=" + path(g.FirmwareCode),
		"-drive", "if=pflash,format=raw,file=" + path(g.FirmwareVars),
		"-drive", "if=none,id=osdisk,format=raw,cache=none,werror=stop,rerror=stop,file=" + path(g.Disk),
		"-device", "ide-hd,drive=osdisk,bus=ide.0,bootindex=1", "-device", "VGA",
		"-netdev", "tap,id=private,script=no,downscript=no,ifname=" + g.Tap,
		"-device", "e1000e,netdev=private,mac=" + MAC(g.ID),
	}, nil
}
