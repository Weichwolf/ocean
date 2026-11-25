package lab

import (
	"bufio"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Up starts a plan. Existing guests keep their disks and configuration.
func (lab *Lab) Up(ctx context.Context, plan Plan, image string, reserveMiB uint, enrollmentFiles ...string) error {
	return lab.UpSelected(ctx, plan, image, reserveMiB, nil, enrollmentFiles...)
}

// UpSelected starts only the selected guests while preserving the full plan.
func (lab *Lab) UpSelected(ctx context.Context, plan Plan, image string, reserveMiB uint,
	selected []string, enrollmentFiles ...string) error {
	lock, err := lab.lock()
	if err != nil {
		return err
	}
	defer lock.Close()

	current, err := lab.load()
	if err != nil {
		return err
	}
	if image == "" {
		image = current.Image
	}
	if image == "" {
		return errors.New("a Debian QCOW2 image is required for a new lab")
	}
	absolute, err := filepath.Abs(image)
	if err != nil {
		return err
	}
	image, err = filepath.EvalSymlinks(absolute)
	if err != nil {
		return err
	}
	digest, err := imageDigest(image)
	if err != nil {
		return fmt.Errorf("read base image: %w", err)
	}
	if current.Image != "" && (current.Image != image || current.ImageDigest != digest) {
		return errors.New("the base image differs from the image backing the existing lab disks")
	}

	wanted := make(map[string]Guest)
	for _, guest := range plan.Guests {
		wanted[guest.Name] = guest
	}
	start := make(map[string]bool, len(selected))
	for _, name := range selected {
		if _, exists := wanted[name]; !exists || start[name] {
			return fmt.Errorf("unknown or duplicate selected guest %q", name)
		}
		start[name] = true
	}
	enrollments := make(map[string]*bootstrapSeed, len(enrollmentFiles))
	for _, manifest := range enrollmentFiles {
		if manifest == "" {
			continue
		}
		seed, err := loadBootstrapSeed(manifest, wanted)
		if err != nil {
			return err
		}
		if enrollments[seed.host] != nil || len(start) > 0 && !start[seed.host] {
			return fmt.Errorf("duplicate or unselected bootstrap manifest for host %s", seed.host)
		}
		enrollments[seed.host] = seed
	}
	machines := make(map[string]Machine)
	for _, machine := range current.Machines {
		if !reflect.DeepEqual(wanted[machine.Guest.Name], machine.Guest) {
			return fmt.Errorf("profile changes or removes %s; use a separate state directory", machine.Guest.Name)
		}
		machines[machine.Guest.Name] = machine
	}
	for host, seed := range enrollments {
		if machine, exists := machines[host]; exists && machine.EnrollmentSeed != seed.digest {
			return fmt.Errorf("host %s already exists with a different provisioning seed", host)
		}
	}
	memory, err := hostMemoryMiB()
	if err != nil {
		return err
	}
	if reserveMiB > memory {
		return errors.New("the configured host memory reserve exceeds available memory")
	}
	budget := memory - reserveMiB
	for _, guest := range plan.Guests {
		if len(start) > 0 && !start[guest.Name] {
			continue
		}
		running, err := lab.running(guest.Name)
		if err != nil {
			return err
		}
		if running {
			if _, known := machines[guest.Name]; !known {
				return fmt.Errorf("running guest %s has no inventory record", guest.Name)
			}
			continue
		}
		if guest.Resources.MemoryMiB > budget {
			return fmt.Errorf("host memory budget exhausted by %s (available %d MiB, reserve %d MiB)", guest.Name, memory, reserveMiB)
		}
		budget -= guest.Resources.MemoryMiB
	}
	kvm, err := os.OpenFile("/dev/kvm", os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("open /dev/kvm: %w", err)
	}
	kvm.Close()
	if err := lab.ensureSSHKey(ctx); err != nil {
		return err
	}

	current.Image, current.ImageDigest = image, digest
	current.Segments = plan.Segments
	if err := lab.save(current); err != nil {
		return err
	}
	for _, segment := range plan.Segments {
		if err := lab.startSwitch(ctx, segment); err != nil {
			return err
		}
	}
	for _, guest := range plan.Guests {
		if len(start) > 0 && !start[guest.Name] {
			continue
		}
		running, err := lab.running(guest.Name)
		if err != nil {
			return err
		}
		if running {
			continue
		}
		port, err := loopbackPort()
		if err != nil {
			return err
		}
		machine := Machine{Guest: guest, SSHPort: port}
		machine.EnrollmentSeed = machines[guest.Name].EnrollmentSeed
		seed := enrollments[guest.Name]
		if seed != nil {
			machine.EnrollmentSeed = seed.digest
		}
		index := slices.IndexFunc(current.Machines, func(record Machine) bool { return record.Guest.Name == guest.Name })
		if index == -1 {
			current.Machines = append(current.Machines, machine)
		} else {
			current.Machines[index] = machine
		}
		if err := lab.save(current); err != nil {
			return err
		}
		if err := lab.startGuest(ctx, machine, image, seed); err != nil {
			return err
		}
	}
	return nil
}

func (lab *Lab) ensureSSHKey(ctx context.Context) error {
	path := filepath.Join(lab.root, "ssh-key")
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return command(ctx, "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", path)
	} else {
		return err
	}
}

func (lab *Lab) startGuest(ctx context.Context, machine Machine, image string, seed *bootstrapSeed) error {
	guest := machine.Guest
	directory := lab.node(guest.Name)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	overlay := filepath.Join(directory, "disk.qcow2")
	if _, err := os.Stat(overlay); errors.Is(err, os.ErrNotExist) {
		partial := filepath.Join(directory, "disk.partial")
		defer os.Remove(partial)
		if err := command(ctx, "qemu-img", "create", "-f", "qcow2", "-F", "qcow2", "-b", image, partial); err != nil {
			return err
		}
		if err := os.Rename(partial, overlay); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	if machine.EnrollmentSeed == "" {
		if err := lab.seed(ctx, guest, nil); err != nil {
			return fmt.Errorf("prepare %s: %w", guest.Name, err)
		}
	} else if _, err := os.Stat(filepath.Join(directory, "seed.iso")); errors.Is(err, os.ErrNotExist) {
		if seed == nil {
			return fmt.Errorf("resume provisioning %s with its original enrollment manifest", guest.Name)
		}
		if err := lab.seed(ctx, guest, seed); err != nil {
			return fmt.Errorf("prepare enrollment for %s: %w", guest.Name, err)
		}
	} else if err != nil {
		return err
	}

	socket := filepath.Join(directory, "qmp")
	if err := os.Remove(socket); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	// Keep guest bootstrap egress separate from the VDE networks used to test tenant paths.
	bootstrap := fmt.Sprintf("user,id=boot,ipv6=off,hostfwd=tcp:127.0.0.1:%d-:22", machine.SSHPort)
	if !slices.Contains(guest.Roles, "compute") {
		bootstrap += ",restrict=on"
	}
	rootDrive := "file=" + escapeQEMU(overlay) + ",format=qcow2,if=virtio"
	if guest.Resources.DataDiskMiB != 0 {
		rootDrive = "file=" + escapeQEMU(overlay) + ",format=qcow2,if=none,id=system"
	}
	args := []string{"-n", "10", "qemu-system-x86_64", "-accel", "kvm", "-cpu", "host", "-machine", "q35",
		"-name", "ocean-" + guest.Name, "-m", strconv.FormatUint(uint64(guest.Resources.MemoryMiB), 10),
		"-smp", strconv.FormatUint(uint64(guest.Resources.VCPUs), 10), "-display", "none", "-monitor", "none", "-daemonize",
		"-qmp", "unix:" + socket + ",server=on,wait=off", "-serial", "file:" + filepath.Join(directory, "serial.log"),
		"-drive", rootDrive,
		"-drive", "file=" + escapeQEMU(filepath.Join(directory, "seed.iso")) + ",format=raw,media=cdrom,readonly=on",
		"-netdev", bootstrap, "-device", "virtio-net-pci,netdev=boot,mac=" + bootstrapMAC(guest),
	}
	if size := guest.Resources.DataDiskMiB; size != 0 {
		path := filepath.Join(directory, "data.qcow2")
		if err := createDataDisk(ctx, path, size); err != nil {
			return fmt.Errorf("prepare storage disk for %s: %w", guest.Name, err)
		}
		args = append(args, "-device", "virtio-blk-pci,drive=system,bootindex=1", "-drive", "file="+escapeQEMU(path)+",format=qcow2,if=none,id=storage",
			"-device", "virtio-blk-pci,drive=storage,serial=ocean-storage")
	}
	if slices.Contains(guest.Roles, "control-plane") {
		args = append(args, "-device", "i6300esb", "-action", "watchdog=reset")
	}
	for index, attachment := range guest.Interfaces {
		id := fmt.Sprintf("net%d", index)
		args = append(args, "-netdev", "vde,id="+id+",sock="+escapeQEMU(filepath.Join(lab.network(attachment.Segment), "data")),
			"-device", "virtio-net-pci,netdev="+id+",mac="+attachment.MAC)
	}
	if err := command(ctx, "nice", args...); err != nil {
		return fmt.Errorf("start %s: %w", guest.Name, err)
	}
	return qmp(socket, "ocean-"+guest.Name, "")
}

// GuestStatus combines the inventory entry and the observed local QEMU state.
type GuestStatus struct {
	Machine
	Running bool `json:"running"`
}

// Status reports the guests recorded in the lab directory.
func (lab *Lab) Status() ([]GuestStatus, error) {
	current, err := lab.load()
	if err != nil {
		return nil, err
	}
	statuses := make([]GuestStatus, 0, len(current.Machines))
	for _, machine := range current.Machines {
		running, err := lab.running(machine.Guest.Name)
		if err != nil {
			return nil, err
		}
		statuses = append(statuses, GuestStatus{Machine: machine, Running: running})
	}
	return statuses, nil
}

func (lab *Lab) running(name string) (bool, error) {
	err := qmp(filepath.Join(lab.node(name), "qmp"), "ocean-"+name, "")
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ECONNREFUSED) {
		return false, nil
	}
	return err == nil, err
}

// Stop terminates one inventoried guest through QMP to exercise abrupt node loss.
func (lab *Lab) Stop(name string) error {
	lock, err := lab.lock()
	if err != nil {
		return err
	}
	defer lock.Close()
	current, err := lab.load()
	if err != nil {
		return err
	}
	if !slices.ContainsFunc(current.Machines, func(machine Machine) bool { return machine.Guest.Name == name }) {
		return fmt.Errorf("unknown guest %q", name)
	}
	return lab.stopGuest(name)
}

func (lab *Lab) stopGuest(name string) error {
	running, err := lab.running(name)
	if err != nil || !running {
		return err
	}
	return qmp(filepath.Join(lab.node(name), "qmp"), "ocean-"+name, "quit")
}

// Down stops the lab guests and switches while preserving disks and inventory.
func (lab *Lab) Down() error {
	lock, err := lab.lock()
	if err != nil {
		return err
	}
	defer lock.Close()
	current, err := lab.load()
	if err != nil {
		return err
	}
	var failures error
	for _, machine := range current.Machines {
		name := machine.Guest.Name
		if err := lab.stopGuest(name); err != nil {
			failures = errors.Join(failures, fmt.Errorf("stop %s: %w", name, err))
		}
	}
	if failures != nil {
		return failures
	}
	for _, segment := range current.Segments {
		if err := lab.stopSwitch(segment); err != nil {
			failures = errors.Join(failures, err)
		}
	}
	return failures
}

// SSH connects to a managed guest through its loopback-only forwarding port.
func (lab *Lab) SSH(ctx context.Context, name string, args []string) error {
	current, err := lab.load()
	if err != nil {
		return err
	}
	index := slices.IndexFunc(current.Machines, func(machine Machine) bool { return machine.Guest.Name == name })
	if index == -1 {
		return fmt.Errorf("unknown guest %q", name)
	}
	machine := current.Machines[index]
	options := []string{"-i", filepath.Join(lab.root, "ssh-key"), "-p", strconv.Itoa(machine.SSHPort), "-o", "IdentitiesOnly=yes",
		"-o", "BatchMode=yes", "-o", "ConnectTimeout=5", "-o", "StrictHostKeyChecking=accept-new",
		"-o", "HostKeyAlias=" + name, "-o", "UserKnownHostsFile=" + filepath.Join(lab.root, "known-hosts"), "ocean@127.0.0.1"}
	process := exec.CommandContext(ctx, "ssh", append(options, args...)...)
	process.Stdin, process.Stdout, process.Stderr = os.Stdin, os.Stdout, os.Stderr
	return process.Run()
}

func imageDigest(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	digest := sha256.New()
	if _, err := io.Copy(digest, file); err != nil {
		return "", err
	}
	return fmt.Sprintf("sha256:%x", digest.Sum(nil)), nil
}

func hostMemoryMiB() (uint, error) {
	file, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 3 && fields[0] == "MemAvailable:" && fields[2] == "kB" {
			memory, err := strconv.ParseUint(fields[1], 10, 64)
			return uint(memory / 1024), err
		}
	}
	if err := scanner.Err(); err != nil {
		return 0, err
	}
	return 0, errors.New("MemAvailable is missing from /proc/meminfo")
}

func loopbackPort() (int, error) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port, nil
}

func escapeQEMU(path string) string {
	return strings.ReplaceAll(path, ",", ",,")
}

func command(ctx context.Context, name string, args ...string) error {
	timeout, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	output, err := exec.CommandContext(timeout, name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %w: %s", name, err, strings.TrimSpace(string(output)))
	}
	return nil
}

// createDataDisk publishes a separate, sparse storage-device image once and
// reuses it when the guest restarts.
func createDataDisk(ctx context.Context, path string, size uint) error {
	info, err := os.Lstat(path)
	if err == nil {
		if !info.Mode().IsRegular() {
			return errors.New("the existing data disk is not a regular file")
		}
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	partial := path + ".partial"
	defer os.Remove(partial)
	if err := command(ctx, "qemu-img", "create", "-f", "qcow2", partial, strconv.FormatUint(uint64(size), 10)+"M"); err != nil {
		return err
	}
	if err := os.Chmod(partial, 0600); err != nil {
		return err
	}
	return os.Rename(partial, path)
}
