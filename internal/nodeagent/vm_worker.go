package nodeagent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"time"

	"github.com/Weichwolf/ocean/internal/config"
	"github.com/Weichwolf/ocean/internal/network"
	"github.com/Weichwolf/ocean/internal/qemu"
	"github.com/Weichwolf/ocean/internal/storage"
	"github.com/Weichwolf/ocean/internal/workload"
	"golang.org/x/sys/unix"
)

const (
	vmRoot    = "/run/ocean-vm"
	vmReady   = vmRoot + "/ready"
	vmAccount = "ocean-vm"
)

var vmIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

type vmWorkerConfig struct {
	Images       string       `json:"imageDirectory"`
	FirmwareCode string       `json:"firmwareCode"`
	DNS          []netip.Addr `json:"dnsServers,omitempty"`
}

type vmWorker struct {
	vmWorkerConfig
	network  containerNetworkConfig
	backend  storage.Backend
	account  *user.User
	uid, gid int
	binary   string
	client   *joinClient
}

type vmLocal struct {
	MachineID  string `json:"machineId"`
	Generation string `json:"generation"`
	DiskID     string `json:"diskId"`
}

func (v vmLocal) valid() bool {
	return vmIDPattern.MatchString(v.MachineID) && vmIDPattern.MatchString(v.Generation) && v.DiskID == "vm-"+v.MachineID
}

type vmJob struct {
	task   workload.VMTask
	cancel context.CancelFunc
	done   chan error
}

// RunVMWorker reconciles local VM resources from authenticated regional
// assignments. Disk import cannot block enrollment heartbeats or firewall leases.
func RunVMWorker(ctx context.Context, base string, logger *slog.Logger) error {
	w, err := openVMWorker(base)
	if err != nil {
		return err
	}
	defer w.client.client.CloseIdleConnections()
	lock, err := os.OpenFile(vmRoot+"/worker.lock", os.O_CREATE|os.O_RDWR|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	defer func() { _ = lock.Close() }()
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return fmt.Errorf("lock VM worker: %w", err)
	}
	defer func() { _ = os.Remove(vmReady) }()
	jobs := make(map[string]vmJob)
	policies := make(map[string]network.WorkloadFirewall)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for ctx.Err() == nil {
		w.collectVMJobs(jobs, logger)
		if err := touchVMReady(); err != nil {
			logger.Warn("VM worker readiness will retry", "error", err)
		}
		round, cancel := context.WithTimeout(ctx, 5*time.Second)
		tasks, err := w.client.vmTasks(round)
		cancel()
		if err == nil {
			w.reconcileVMJobs(ctx, tasks, jobs, policies, logger)
		} else if ctx.Err() == nil {
			logger.Warn("VM assignments will retry", "error", err)
		}
		select {
		case <-ctx.Done():
		case <-ticker.C:
		}
	}
	for _, job := range jobs {
		job.cancel()
	}
	return w.shutdownVMWorker(jobs, logger)
}

func openVMWorker(base string) (vmWorker, error) {
	var w vmWorker
	if os.Geteuid() != 0 {
		return w, errors.New("VM networking and storage require the system VM worker")
	}
	var err error
	w.vmWorkerConfig, err = config.Load(filepath.Join(base, "vm.json"), vmWorkerConfig{FirmwareCode: "/usr/share/OVMF/OVMF_CODE_4M.fd"})
	if err != nil {
		return w, err
	}
	for _, path := range []string{w.Images, w.FirmwareCode} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return w, errors.New("VM images and firmware require explicit absolute paths")
		}
	}
	for _, ip := range w.DNS {
		if !ip.Is4() || !ip.IsGlobalUnicast() {
			return w, errors.New("VM DNS servers must use unicast IPv4 addresses")
		}
	}
	w.network, err = config.Load(filepath.Join(base, "workload-network.json"), containerNetworkConfig{})
	if err != nil {
		return w, err
	}
	if err := w.network.validate(); err != nil {
		return w, err
	}
	disks, err := config.Load(filepath.Join(base, "storage.json"), storage.Config{})
	if err != nil {
		return w, err
	}
	w.backend, err = storage.Open(disks)
	if err != nil {
		return w, err
	}
	for _, path := range []string{w.FirmwareCode, "/usr/bin/qemu-system-x86_64", "/usr/bin/qemu-img", "/usr/bin/rbd",
		"/usr/bin/arping", "/usr/sbin/dnsmasq", "/dev/net/tun"} {
		if _, err := os.Stat(path); err != nil {
			return w, fmt.Errorf("VM worker prerequisite: %w", err)
		}
	}
	w.account, err = user.Lookup(vmAccount)
	if err != nil {
		return w, err
	}
	uid, uidErr := strconv.Atoi(w.account.Uid)
	gid, gidErr := strconv.Atoi(w.account.Gid)
	if uidErr != nil || gidErr != nil || uid < 1 || gid < 1 {
		return w, errors.New("VM worker requires a dedicated unprivileged runtime account")
	}
	w.uid, w.gid = uid, gid
	w.binary, err = os.Executable()
	if err != nil {
		return w, err
	}
	if err := exec.Command("/usr/sbin/runuser", "-u", vmAccount, "--", w.binary, "-mode", "vm-guest", "-vm-action", "check").Run(); err != nil {
		return w, errors.New("the VM runtime account cannot open /dev/kvm")
	}
	if err := prepareVMRuntime(vmRoot); err != nil {
		return w, err
	}
	w.client, err = loadEnrolledClient(filepath.Join(base, "config.json"))
	return w, err
}

func prepareVMRuntime(root string) error {
	if err := os.MkdirAll(root, 0755); err != nil {
		return err
	}
	// Older workers could create the parent with the private locals mode.
	// The unprivileged enrollment agent must be able to stat the ready file.
	if err := os.Chmod(root, 0755); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(root, "locals"), 0700); err != nil {
		return err
	}
	return os.MkdirAll(filepath.Join(root, "guests"), 0755)
}

func touchVMReady() error {
	now := time.Now()
	err := os.Chtimes(vmReady, now, now)
	if errors.Is(err, os.ErrNotExist) {
		return publishFile(vmReady, nil)
	}
	return err
}

func (w vmWorker) collectVMJobs(jobs map[string]vmJob, logger *slog.Logger) {
	for id, job := range jobs {
		select {
		case err := <-job.done:
			job.cancel()
			delete(jobs, id)
			if err != nil && !errors.Is(err, context.Canceled) {
				logger.Warn("VM operation will retry", "machine", id, "error", err)
			}
		default:
		}
	}
}

func (w vmWorker) reconcileVMJobs(ctx context.Context, tasks []workload.VMTask, jobs map[string]vmJob,
	policies map[string]network.WorkloadFirewall, logger *slog.Logger) {
	seen := make(map[string]workload.VMTask, len(tasks))
	for _, task := range tasks {
		seen[task.MachineID] = task
	}
	for id, job := range jobs {
		latest, assigned := seen[id]
		if job.task.MachineID == "" && assigned || job.task.MachineID != "" &&
			(!assigned || latest.AssignmentID != job.task.AssignmentID || latest.State != job.task.State) {
			job.cancel()
		}
	}
	for _, task := range tasks {
		if task.State == workload.Running {
			w.refreshVMPolicy(ctx, task, policies, logger)
		} else {
			delete(policies, task.MachineID)
		}
		if _, running := jobs[task.MachineID]; !running && len(jobs) < 4 {
			jobCtx, cancel := context.WithTimeout(ctx, 15*time.Minute)
			job := vmJob{task: task, cancel: cancel, done: make(chan error, 1)}
			jobs[task.MachineID] = job
			go func() {
				defer clear(task.VolumeKey)
				job.done <- w.applyVMTask(jobCtx, task)
			}()
		} else {
			clear(task.VolumeKey)
		}
	}
	locals, err := listLocalVMs()
	if err != nil {
		logger.Warn("VM local inventory will retry", "error", err)
		return
	}
	for _, local := range locals {
		if _, assigned := seen[local.MachineID]; assigned {
			continue
		}
		delete(policies, local.MachineID)
		if _, running := jobs[local.MachineID]; running || len(jobs) >= 4 {
			continue
		}
		jobCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		job := vmJob{cancel: cancel, done: make(chan error, 1)}
		jobs[local.MachineID] = job
		go func() { job.done <- w.withdrawVM(jobCtx, local, false) }()
	}
}

func (w vmWorker) refreshVMPolicy(ctx context.Context, task workload.VMTask, installed map[string]network.WorkloadFirewall, logger *slog.Logger) {
	ns := vmNamespace(task.MachineID)
	if _, err := os.Stat(filepath.Join("/run/netns", ns)); err != nil {
		delete(installed, task.MachineID)
		return
	}
	policy, err := w.firewall(task)
	if err != nil {
		logger.Warn("VM network policy refused", "machine", task.MachineID, "error", err)
		return
	}
	update, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	if !reflect.DeepEqual(installed[task.MachineID], policy) || policy.Refresh(update, ns) != nil {
		if err := policy.Apply(update, ns); err != nil {
			logger.Warn("VM firewall refresh will retry", "machine", task.MachineID, "error", err)
			return
		}
	}
	installed[task.MachineID] = policy
}

func (w vmWorker) shutdownVMWorker(jobs map[string]vmJob, logger *slog.Logger) error {
	shutdown, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	for id, job := range jobs {
		select {
		case err := <-job.done:
			if err != nil && !errors.Is(err, context.Canceled) {
				logger.Warn("VM operation failed during shutdown", "machine", id, "error", err)
			}
		case <-shutdown.Done():
			return shutdown.Err()
		}
	}
	locals, err := listLocalVMs()
	if err != nil {
		return err
	}
	var failures error
	for _, local := range locals {
		failures = errors.Join(failures, w.withdrawVM(shutdown, local, false))
	}
	return failures
}

func localVMPath(id string) string { return filepath.Join(vmRoot, "locals", id+".json") }

func listLocalVMs() ([]vmLocal, error) {
	entries, err := os.ReadDir(vmRoot + "/locals")
	if err != nil {
		return nil, err
	}
	var results []vmLocal
	for _, entry := range entries {
		id := entry.Name()
		if filepath.Ext(id) != ".json" || !vmIDPattern.MatchString(id[:len(id)-5]) {
			continue
		}
		var v vmLocal
		data, err := os.ReadFile(filepath.Join(vmRoot, "locals", id))
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		if err == nil && json.Unmarshal(data, &v) == nil && v.valid() && id == v.MachineID+".json" {
			results = append(results, v)
		}
	}
	return results, nil
}

func (w vmWorker) applyVMTask(ctx context.Context, task workload.VMTask) error {
	current := vmLocal{task.MachineID, task.Generation, task.Disk.ID}
	data, err := os.ReadFile(localVMPath(current.MachineID))
	if err == nil {
		var prior vmLocal
		if json.Unmarshal(data, &prior) != nil || !prior.valid() || prior.MachineID != current.MachineID {
			return errors.New("invalid local VM ownership record")
		}
		if prior != current {
			if err := w.withdrawVM(ctx, prior, false); err != nil {
				return err
			}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if task.State == workload.Suspended {
		if err := w.suspendVM(ctx, current); err != nil {
			return err
		}
		return w.client.reportVM(ctx, task, task.State)
	}
	if task.State != workload.Running {
		if err := w.withdrawVM(ctx, current, task.Force); err != nil {
			return err
		}
		if task.State == workload.Removed {
			if err := w.client.confirmVMTask(ctx, task); err != nil {
				return err
			}
			if err := w.backend.Remove(ctx, current.DiskID); err != nil {
				return err
			}
		}
		return w.client.reportVM(ctx, task, task.State)
	}
	data, _ = json.Marshal(current)
	if err := publishFile(localVMPath(current.MachineID), data); err != nil {
		return err
	}
	guest, err := w.localGuest(current, task.Size)
	if err != nil {
		return err
	}
	state, err := w.runGuest(ctx, guest, "status", false)
	if err != nil {
		return err
	}
	if state == qemu.PowerOff {
		if err := w.startVM(ctx, task, guest); err != nil {
			return err
		}
	} else if state != qemu.PowerRunning {
		return fmt.Errorf("VM reports unexpected QEMU power state %q", state)
	}
	if err := waitVMNetwork(ctx, task); err != nil {
		return err
	}
	return w.client.reportVM(ctx, task, workload.Running)
}

func (w vmWorker) startVM(ctx context.Context, task workload.VMTask, guest qemu.Guest) error {
	if !task.Prepared {
		source := storage.VMPaths{Disk: filepath.Join(w.Images, task.Disk.ImageSHA256+".raw"),
			FirmwareVars: filepath.Join(w.Images, task.Disk.FirmwareSHA256+".fd")}
		if err := w.backend.InitializeVMDisk(ctx, task.Disk, task.VolumeKey, source); err != nil {
			return err
		}
	}
	if _, err := w.backend.AttachVMDisk(ctx, task.Disk, task.VolumeKey, w.uid, w.gid); err != nil {
		return err
	}
	if err := w.prepareVMNetwork(ctx, task); err != nil {
		return err
	}
	if err := w.client.confirmVMTask(ctx, task); err != nil {
		return err
	}
	_, err := w.runGuest(ctx, guest, "start", false)
	return err
}

func (w vmWorker) suspendVM(ctx context.Context, local vmLocal) error {
	grace, cancel := context.WithTimeout(ctx, 15*time.Second)
	err := w.withdrawVM(grace, local, false)
	expired := errors.Is(grace.Err(), context.DeadlineExceeded)
	cancel()
	if err != nil && expired && ctx.Err() == nil {
		return w.withdrawVM(ctx, local, true)
	}
	return err
}

func (w vmWorker) withdrawVM(ctx context.Context, local vmLocal, force bool) error {
	guest, err := w.localGuest(local, "")
	if err != nil {
		return err
	}
	stop, cancel := context.WithTimeout(ctx, 75*time.Second)
	defer cancel()
	if _, err := w.runGuest(stop, guest, "stop", force); err != nil {
		return err
	}
	if err := removeVMNetwork(ctx, vmNamespace(local.MachineID)); err != nil {
		return err
	}
	if err := w.backend.Unmount(ctx, local.DiskID); err != nil {
		return err
	}
	if err := os.Remove(localVMPath(local.MachineID)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func (w vmWorker) localGuest(local vmLocal, size string) (qemu.Guest, error) {
	if !local.valid() {
		return qemu.Guest{}, errors.New("invalid local VM identity")
	}
	path := filepath.Join(vmRoot, "guests", local.MachineID)
	if err := os.Mkdir(path, 0700); err == nil {
		if err := os.Chown(path, w.uid, w.gid); err != nil {
			return qemu.Guest{}, err
		}
	} else if !errors.Is(err, os.ErrExist) {
		return qemu.Guest{}, err
	}
	files := w.backend.VMPaths(local.DiskID)
	return qemu.Guest{ID: local.MachineID, Generation: local.Generation, Size: size, Directory: path, Disk: files.Disk,
		FirmwareCode: w.FirmwareCode, FirmwareVars: files.FirmwareVars, Tap: vmTap}, nil
}

func (w vmWorker) runGuest(ctx context.Context, guest qemu.Guest, action string, force bool) (qemu.PowerState, error) {
	args := []string{"-u", vmAccount, "--", w.binary, "-mode", "vm-guest", "-vm-action", action}
	binary := "/usr/sbin/runuser"
	if action == "start" {
		args = append([]string{"netns", "exec", vmNamespace(guest.ID), binary}, args...)
		binary = "/usr/bin/ip"
	}
	data, _ := json.Marshal(vmGuestCommand{Guest: guest, Force: force})
	command := exec.CommandContext(ctx, binary, args...)
	command.Stdin = bytes.NewReader(data)
	command.Stderr = os.Stderr
	output, err := command.Output()
	if err != nil {
		return "", fmt.Errorf("VM guest %s: %w", action, err)
	}
	return qemu.PowerState(output), nil
}

type vmGuestCommand struct {
	Guest qemu.Guest
	Force bool
}

// RunVMGuestControl is the unprivileged QEMU entry point used by the system
// worker. Start inherits the private guest namespace chosen by the worker.
func RunVMGuestControl(ctx context.Context, action string, input io.Reader, output io.Writer) error {
	account, err := user.Lookup(vmAccount)
	if err != nil || os.Geteuid() == 0 || strconv.Itoa(os.Geteuid()) != account.Uid {
		return errors.New("KVM guest control requires the dedicated runtime account")
	}
	if action == "check" {
		device, err := os.OpenFile("/dev/kvm", os.O_RDWR, 0)
		if err != nil {
			return err
		}
		return device.Close()
	}
	var command vmGuestCommand
	decoder := json.NewDecoder(io.LimitReader(input, 16<<10))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&command) != nil || decoder.Decode(new(any)) != io.EOF {
		return errors.New("invalid VM guest command")
	}
	switch action {
	case "status":
		state, err := command.Guest.Status(ctx)
		if err != nil {
			return err
		}
		_, err = io.WriteString(output, string(state))
		return err
	case "start":
		return command.Guest.Start(ctx)
	case "stop":
		return command.Guest.Stop(ctx, command.Force)
	default:
		return errors.New("unsupported VM guest action")
	}
}
