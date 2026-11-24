package lab

import (
	"encoding/json"
	"fmt"
	"net"
	"time"
)

func qmp(path, name, command string) error {
	connection, err := net.DialTimeout("unix", path, time.Second)
	if err != nil {
		return err
	}
	defer connection.Close()
	if err := connection.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		return err
	}
	decoder, encoder := json.NewDecoder(connection), json.NewEncoder(connection)
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
	return request(command, nil)
}
