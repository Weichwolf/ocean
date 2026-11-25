// Package harness records and runs local black-box acceptance probes.
package harness

import (
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
)

var caseID = regexp.MustCompile(`^[A-Z][A-Z0-9]*-[0-9]{2}$`)

type Case struct {
	ID            string
	Gate          string
	Environment   string
	Area          string
	Scenario      string
	Interface     string
	Preconditions string
	Procedure     string
	PassCriteria  string
}

func ReadCatalog(path string) ([]Case, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	rows := csv.NewReader(file)
	rows.Comma = '\t'
	rows.FieldsPerRecord = 9
	header, err := rows.Read()
	if err != nil {
		return nil, err
	}
	if strings.Join(header, "\t") != "id\tgate\tenvironment\tarea\tscenario\tinterface\tpreconditions\tprocedure\tpass_criteria" {
		return nil, errors.New("invalid acceptance matrix header")
	}
	seen := make(map[string]bool)
	var cases []Case
	for {
		line, err := rows.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		gate := line[1]
		if !caseID.MatchString(line[0]) || seen[line[0]] ||
			(gate != "required" && gate != "production" && gate != "conditional") {
			return nil, fmt.Errorf("invalid acceptance case %q", line[0])
		}
		for _, field := range line {
			if strings.TrimSpace(field) == "" {
				return nil, fmt.Errorf("acceptance case %s has an empty field", line[0])
			}
		}
		seen[line[0]] = true
		cases = append(cases, Case{ID: line[0], Gate: gate, Environment: line[2], Area: line[3], Scenario: line[4],
			Interface: line[5], Preconditions: line[6], Procedure: line[7], PassCriteria: line[8]})
	}
	if len(cases) == 0 {
		return nil, errors.New("the acceptance matrix is empty")
	}
	return cases, nil
}

type CommandContract struct {
	Case       string
	Name       string
	CLI        string
	Extensions string
	APIVersion string
	Command    string
}

func ReadContract(path string, cases []Case) ([]CommandContract, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	rows := csv.NewReader(file)
	rows.Comma = '\t'
	rows.FieldsPerRecord = 6
	header, err := rows.Read()
	if err != nil {
		return nil, err
	}
	if strings.Join(header, "\t") != "case_id\tcommand_id\tazure_cli\textensions\tapi_version\tcommand" {
		return nil, errors.New("invalid CLI contract header")
	}
	known := make(map[string]bool)
	for _, c := range cases {
		known[c.ID] = true
	}
	var commands []CommandContract
	seen := make(map[string]bool)
	for {
		row, err := rows.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		key := row[0] + "/" + row[1]
		if !known[row[0]] || seen[key] {
			return nil, fmt.Errorf("unknown or duplicate CLI contract %s", key)
		}
		for _, field := range row {
			if strings.TrimSpace(field) == "" {
				return nil, fmt.Errorf("CLI contract %s has an empty field", key)
			}
		}
		seen[key] = true
		commands = append(commands, CommandContract{Case: row[0], Name: row[1], CLI: row[2], Extensions: row[3], APIVersion: row[4], Command: row[5]})
	}
	if len(commands) == 0 {
		return nil, errors.New("the CLI contract is empty")
	}
	return commands, nil
}
