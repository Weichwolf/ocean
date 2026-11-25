// Package qemu controls QEMU through a private local monitor.
package qemu

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

// Call verifies the guest name before issuing one monitor command. A blank
// command verifies the connection and guest identity only.
func Call(ctx context.Context, path, name, command string, result any) error {
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	connection, err := (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "unix", path)
	if err != nil {
		return err
	}
	defer func() { _ = connection.Close() }()
	deadline, _ := ctx.Deadline()
	if err := connection.SetDeadline(deadline); err != nil {
		return err
	}
	decoder, encoder := json.NewDecoder(io.LimitReader(connection, 1<<20)), json.NewEncoder(connection)
	var greeting struct {
		QMP json.RawMessage `json:"QMP"`
	}
	if err := decoder.Decode(&greeting); err != nil {
		return err
	}
	if greeting.QMP == nil {
		return fmt.Errorf("invalid QMP greeting at %s", path)
	}
	request := func(name string, destination any) error {
		if err := encoder.Encode(map[string]string{"execute": name}); err != nil {
			return err
		}
		for {
			var response struct {
				Return json.RawMessage `json:"return"`
				Error  *struct {
					Description string `json:"desc"`
				} `json:"error"`
			}
			if err := decoder.Decode(&response); err != nil {
				return err
			}
			if response.Error != nil {
				return fmt.Errorf("QMP %s: %s", name, response.Error.Description)
			}
			if response.Return != nil {
				if destination != nil {
					return json.Unmarshal(response.Return, destination)
				}
				return nil
			}
		}
	}
	if err := request("qmp_capabilities", nil); err != nil {
		return err
	}
	var identity struct {
		Name string `json:"name"`
	}
	if err := request("query-name", &identity); err != nil {
		return err
	}
	if identity.Name != name {
		return fmt.Errorf("wrong guest at %s: got %q, want %q", path, identity.Name, name)
	}
	if command == "" {
		return nil
	}
	err = request(command, result)
	if command == "quit" && errors.Is(err, io.EOF) {
		return nil // QEMU can close the monitor before acknowledging quit.
	}
	return err
}
