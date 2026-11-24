package lab

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

func (lab *Lab) startSwitch(ctx context.Context, name string) error {
	directory := lab.network(name)
	socket := filepath.Join(directory, "mgmt")
	if connection, err := connectSwitch(socket); err != nil {
		return err
	} else if connection != nil {
		return connection.Close()
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	if err := os.Remove(socket); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	data := filepath.Join(directory, "data")
	// A terminated switch can leave its private control directory behind.
	if err := os.RemoveAll(data); err != nil {
		return err
	}
	if err := command(ctx, "vde_switch", "--daemon", "--rcfile", "/dev/null", "--sock", data, "--mgmt", socket,
		"--mode", "0600", "--dirmode", "0700", "--mgmtmode", "0600"); err != nil {
		return fmt.Errorf("start switch %s: %w", name, err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		connection, err := connectSwitch(socket)
		if err != nil {
			return err
		}
		if connection != nil {
			return connection.Close()
		}
		time.Sleep(25 * time.Millisecond)
	}
	return fmt.Errorf("switch %s did not open its management socket", name)
}

func (lab *Lab) stopSwitch(name string) error {
	socket := filepath.Join(lab.network(name), "mgmt")
	connection, err := connectSwitch(socket)
	if err != nil || connection == nil {
		return err
	}
	if err := connection.SetWriteDeadline(time.Now().Add(time.Second)); err == nil {
		_, err = connection.Write([]byte("shutdown\n"))
	}
	closeErr := connection.Close()
	if err != nil || closeErr != nil {
		return errors.Join(err, closeErr)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		connection, err := connectSwitch(socket)
		if err != nil || connection == nil {
			return err
		}
		connection.Close()
		time.Sleep(25 * time.Millisecond)
	}
	return fmt.Errorf("switch %s did not stop", name)
}

func connectSwitch(path string) (net.Conn, error) {
	connection, err := net.DialTimeout("unix", path, time.Second)
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ECONNREFUSED) {
		return nil, nil
	}
	return connection, err
}
