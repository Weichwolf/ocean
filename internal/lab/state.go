package lab

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// Machine contains the persistent inventory record for one launched guest.
type Machine struct {
	Guest   Guest `json:"guest"`
	SSHPort int   `json:"sshPort"`
}

type state struct {
	Image       string    `json:"image"`
	ImageDigest string    `json:"imageDigest"`
	Segments    []string  `json:"segments"`
	Machines    []Machine `json:"machines"`
}

// Lab keeps a private workspace for disks, seeds, and local control sockets.
type Lab struct {
	root string
}

// Open opens an isolated lab directory owned by the current user.
func Open(path string) (*Lab, error) {
	if path == "" {
		return nil, errors.New("a lab state directory is required")
	}
	root, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, err
	}
	// Preserve room in Linux Unix socket addresses for generated names.
	if len(filepath.Join(root, "networks", "f4-management", "data", "ctl")) > 107 {
		return nil, errors.New("lab state path is too long for Unix control sockets")
	}
	info, err := os.Lstat(root)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode().Perm()&0o077 != 0 || info.Sys().(*syscall.Stat_t).Uid != uint32(os.Getuid()) {
		return nil, errors.New("the lab state directory must be private and owned by the current user")
	}
	return &Lab{root: root}, nil
}

func (lab *Lab) lock() (*os.File, error) {
	file, err := os.OpenFile(filepath.Join(lab.root, "lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		file.Close()
		return nil, fmt.Errorf("lock lab state: %w", err)
	}
	return file, nil
}

func (lab *Lab) load() (state, error) {
	data, err := os.ReadFile(filepath.Join(lab.root, "state.json"))
	if errors.Is(err, os.ErrNotExist) {
		return state{}, nil
	}
	if err != nil {
		return state{}, err
	}
	var current state
	if err := json.Unmarshal(data, &current); err != nil {
		return state{}, fmt.Errorf("read lab state: %w", err)
	}
	return current, nil
}

func (lab *Lab) save(current state) error {
	temporary, err := os.CreateTemp(lab.root, ".state-*")
	if err != nil {
		return err
	}
	defer os.Remove(temporary.Name())
	encoder := json.NewEncoder(temporary)
	encoder.SetIndent("", "  ")
	err = encoder.Encode(current)
	if closeErr := temporary.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(temporary.Name(), filepath.Join(lab.root, "state.json"))
}

func (lab *Lab) node(name string) string {
	return filepath.Join(lab.root, "nodes", name)
}

func (lab *Lab) network(name string) string {
	return filepath.Join(lab.root, "networks", name)
}
