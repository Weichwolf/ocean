package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Weichwolf/ocean/internal/lab"
)

const usage = `usage: ocean-lab <command> [options]

  plan   -profile FILE
  up     -state DIR -profile FILE [-image QCOW2] [-reserve-mib 2048] [-enrollment-file FILE ...] [-only GUEST ...]
  status -state DIR
  ssh    -state DIR GUEST [-- COMMAND]
  stop   -state DIR GUEST
  down   -state DIR
  shutdown -state DIR`

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "ocean-lab: %v\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("%s", usage)
	}
	if args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		fmt.Println(usage)
		return nil
	}
	operation := args[0]
	flags := flag.NewFlagSet(operation, flag.ContinueOnError)
	flags.Usage = func() { _, _ = fmt.Fprintln(flags.Output(), usage) }
	var profilePath, statePath, image string
	var enrollmentFiles, selected []string
	var reserve uint
	switch operation {
	case "plan", "up":
		flags.StringVar(&profilePath, "profile", "", "path to a YAML lab profile")
	case "status", "ssh", "stop", "down", "shutdown":
	default:
		return fmt.Errorf("unknown command %q\n%s", operation, usage)
	}
	if operation != "plan" {
		flags.StringVar(&statePath, "state", "", "private local lab directory")
	}
	if operation == "up" {
		flags.StringVar(&image, "image", "", "Debian QCOW2 base image for a new lab")
		flags.UintVar(&reserve, "reserve-mib", 2048, "host memory to keep available in MiB")
		flags.Func("only", "guest from the full profile to start, repeat for multiple guests", func(name string) error {
			if name == "" {
				return fmt.Errorf("-only requires a guest name")
			}
			selected = append(selected, name)
			return nil
		})
		flags.Func("enrollment-file", "bootstrap manifest for a new approved host, repeat for multiple hosts", func(path string) error {
			if path == "" {
				return fmt.Errorf("-enrollment-file requires a path")
			}
			enrollmentFiles = append(enrollmentFiles, path)
			return nil
		})
	}
	if err := flags.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if operation == "ssh" && flags.NArg() < 1 || operation == "stop" && flags.NArg() != 1 ||
		operation != "ssh" && operation != "stop" && flags.NArg() != 0 {
		return fmt.Errorf("%s", usage)
	}
	var plan lab.Plan
	if operation == "plan" || operation == "up" {
		if profilePath == "" {
			return fmt.Errorf("-profile is required")
		}
		var err error
		plan, err = lab.LoadPlan(profilePath)
		if err != nil {
			return err
		}
	}
	if operation == "plan" {
		return printJSON(plan)
	}
	workspace, err := lab.Open(statePath)
	if err != nil {
		return err
	}
	switch operation {
	case "up":
		if len(selected) != 0 {
			return workspace.UpSelected(ctx, plan, image, reserve, selected, enrollmentFiles...)
		}
		return workspace.Up(ctx, plan, image, reserve, enrollmentFiles...)
	case "status":
		guests, err := workspace.Status()
		if err != nil {
			return err
		}
		return printJSON(guests)
	case "down":
		return workspace.Down()
	case "shutdown":
		deadline, cancel := context.WithTimeout(ctx, 150*time.Second)
		defer cancel()
		return workspace.Shutdown(deadline)
	case "stop":
		return workspace.Stop(flags.Arg(0))
	case "ssh":
		remote := flags.Args()[1:]
		if len(remote) > 0 && remote[0] == "--" {
			remote = remote[1:]
		}
		return workspace.SSH(ctx, flags.Arg(0), remote)
	}
	return nil
}

func printJSON(value any) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}
