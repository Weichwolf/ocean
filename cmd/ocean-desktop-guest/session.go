package main

import (
	"context"
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

	"github.com/Weichwolf/ocean/internal/desktop"
	"golang.org/x/sys/unix"
)

const guestExecutable = "/usr/libexec/ocean/ocean-desktop-guest"

type nativeSession struct {
	id     string
	uid    int
	leader int
}

var nativeSessionID = regexp.MustCompile(`^c?[1-9][0-9]{0,19}$`)

func (s nativeSession) valid() bool {
	return nativeSessionID.MatchString(s.id) && s.uid >= 1000 && s.leader > 1
}

func (s nativeSession) scope() string { return "session-" + s.id + ".scope" }

func (s nativeSession) matches(ctx context.Context) bool {
	if !s.valid() {
		return false
	}
	result, err := exec.CommandContext(ctx, "/usr/bin/loginctl", "show-session", s.id,
		"--property=Service", "--property=Scope", "--property=User", "--property=Leader").Output()
	if err != nil {
		return false
	}
	properties := make(map[string]string, 4)
	for line := range strings.SplitSeq(string(result), "\n") {
		if key, value, ok := strings.Cut(line, "="); ok {
			properties[key] = value
		}
	}
	return properties["Service"] == "xrdp-sesman" && properties["Scope"] == s.scope() &&
		properties["User"] == strconv.Itoa(s.uid) && properties["Leader"] == strconv.Itoa(s.leader)
}

func (s nativeSession) args() []string {
	return []string{"-session", s.id, "-uid", strconv.Itoa(s.uid), "-leader", strconv.Itoa(s.leader)}
}

func startNativeSession(path, account string) bool {
	config, err := loadGuestConfig(path)
	if err != nil {
		return false
	}
	if config.Native == nil {
		return true
	}
	account = strings.ToLower(account)
	if !desktop.ValidNativeAccount(account) {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 9*time.Second)
	defer cancel()
	uid, err := workforceUID(ctx, account)
	target := nativeSession{id: os.Getenv("XDG_SESSION_ID"), uid: uid, leader: os.Getppid()}
	if err != nil || !target.matches(ctx) {
		return false
	}
	kill, inode, err := target.openScopeKill()
	if err != nil || kill.Close() != nil {
		return false
	}
	stop := append([]string{guestExecutable, "-mode", "end-native"}, target.args()...)
	stop = append(stop, "-scope-inode", strconv.FormatUint(inode, 10))
	args := []string{"--quiet", "--collect", "--expand-environment=no", "--unit=ocean-desktop-session-" + target.id,
		"--property=Type=notify", "--property=TimeoutStartSec=6s", "--property=WatchdogSec=10s",
		"--property=WatchdogSignal=SIGKILL", "--property=ExecStopPost=" + strings.Join(stop, " "),
		"--", guestExecutable, "-mode", "watch-native", "-config", path}
	args = append(args, target.args()...)
	return exec.CommandContext(ctx, "/usr/bin/systemd-run", args...).Run() == nil
}

func systemdNotify(value string) error {
	socket := os.Getenv("NOTIFY_SOCKET")
	if socket == "" {
		return errors.New("native desktop monitor has no systemd notifier")
	}
	conn, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: socket, Net: "unixgram"})
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	if err := conn.SetWriteDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
		return err
	}
	_, err = conn.Write([]byte(value))
	return err
}

func watchNativeSession(path string, target nativeSession) error {
	config, err := loadGuestConfig(path)
	if err != nil || config.Native == nil {
		return errors.New("invalid native desktop monitor configuration")
	}
	check, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if !target.matches(check) {
		return errors.New("native desktop monitor could not verify the XRDP session")
	}
	account, uid, err := workforcePasswd(check, strconv.Itoa(target.uid))
	if err != nil || uid != target.uid || !desktop.ValidNativeAccount(account) {
		return errors.New("native desktop monitor could not verify the workforce account")
	}
	pid, err := unix.PidfdOpen(target.leader, 0)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(pid) }()
	client, err := config.Native.client()
	if err != nil {
		return err
	}
	defer client.CloseIdleConnections()
	fetch := func(deadline time.Time) (desktop.NativeLease, error) {
		ctx, stop := context.WithDeadline(context.Background(), deadline)
		defer stop()
		return readNativeLease(ctx, client, config.Native.Region, account, config.MachineID)
	}
	lease, err := fetch(time.Now().Add(3 * time.Second))
	if err != nil {
		return err
	}
	if err := systemdNotify("READY=1\nWATCHDOG=1"); err != nil {
		return err
	}
	delay := 4 * time.Second
	for time.Now().Before(lease.ExpiresAt) {
		checkedAt := minDeadline(lease.ExpiresAt, time.Now().Add(delay))
		ended, err := waitForSessionExit(pid, checkedAt)
		if err != nil {
			return err
		}
		if ended {
			return nil
		}
		if !time.Now().Before(lease.ExpiresAt) {
			break
		}
		next, err := fetch(minDeadline(lease.ExpiresAt, time.Now().Add(3*time.Second)))
		if !time.Now().Before(lease.ExpiresAt) {
			break
		}
		if errors.Is(err, errNativeDenied) {
			return err
		}
		if err != nil {
			delay = 500 * time.Millisecond
			continue
		}
		if !sameNativeAssignment(lease, next) {
			return errors.New("the native desktop assignment changed")
		}
		lease = next
		delay = 4 * time.Second
		if err := systemdNotify("WATCHDOG=1"); err != nil {
			return err
		}
	}
	return errors.New("the native desktop authorization expired")
}

func waitForSessionExit(pid int, until time.Time) (bool, error) {
	events := []unix.PollFd{{Fd: int32(pid), Events: unix.POLLIN}}
	for {
		remaining := time.Until(until)
		if remaining <= 0 {
			return false, nil
		}
		ready, err := unix.Poll(events, int(remaining.Round(time.Millisecond).Milliseconds()))
		if !errors.Is(err, unix.EINTR) {
			return ready != 0, err
		}
	}
}

func minDeadline(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func (s nativeSession) openScopeKill() (*os.File, uint64, error) {
	if !s.valid() {
		return nil, 0, errors.New("invalid XRDP session scope")
	}
	path := filepath.Join("/sys/fs/cgroup/user.slice", "user-"+strconv.Itoa(s.uid)+".slice", s.scope(), "cgroup.kill")
	file, err := os.OpenFile(path, os.O_WRONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, 0, err
	}
	var info unix.Stat_t
	var filesystem unix.Statfs_t
	if unix.Fstat(int(file.Fd()), &info) != nil || unix.Fstatfs(int(file.Fd()), &filesystem) != nil ||
		info.Uid != 0 || info.Mode&unix.S_IFMT != unix.S_IFREG || filesystem.Type != unix.CGROUP2_SUPER_MAGIC || info.Ino == 0 {
		_ = file.Close()
		return nil, 0, errors.New("invalid XRDP session kill control")
	}
	return file, info.Ino, nil
}

func endNativeSession(target nativeSession, expected uint64) error {
	file, inode, err := target.openScopeKill()
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()
	if inode != expected {
		return errors.New("XRDP session kill control changed")
	}
	if _, err := file.WriteString("1\n"); err != nil {
		return fmt.Errorf("close the XRDP session scope: %w", err)
	}
	return nil
}
