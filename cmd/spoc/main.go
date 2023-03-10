/*
Copyright 2023 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/urfave/cli/v2"

	"sigs.k8s.io/security-profiles-operator/cmd"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/cli/recorder"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/cli/runner"
)

func main() {
	app, _ := cmd.DefaultApp()
	app.Usage = "Security Profiles Operator CLI"

	app.Commands = append(app.Commands,
		&cli.Command{
			Name:      "record",
			Aliases:   []string{"r"},
			Usage:     "run a command and record the security profile",
			Action:    record,
			ArgsUsage: "COMMAND",
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:        recorder.FlagOutputFile,
					Aliases:     []string{"o"},
					Usage:       "the output file path for the recorded profile",
					DefaultText: recorder.DefaultOutputFile,
					TakesFile:   true,
				},
				&cli.StringFlag{
					Name:    recorder.FlagType,
					Aliases: []string{"t"},
					Usage:   "the record type",
					DefaultText: fmt.Sprintf(
						"%s [alternative: %s]",
						recorder.TypeSeccomp,
						recorder.TypeRawSeccomp,
					),
				},
				&cli.StringSliceFlag{
					Name:    recorder.FlagBaseSyscalls,
					Aliases: []string{"b"},
					Usage: "base syscalls to be included in every profile " +
						"to ensure compatibility with OCI runtimes like runc and crun",
					DefaultText: strings.Join(recorder.DefaultBaseSyscalls, ", "),
				},
				&cli.BoolFlag{
					Name:    recorder.FlagNoBaseSyscalls,
					Aliases: []string{"n"},
					Usage:   "do not add any base syscalls at all",
				},
			},
		},
		&cli.Command{
			Name:      "run",
			Aliases:   []string{"x"},
			Usage:     "run a command using a security profile",
			Action:    run,
			ArgsUsage: "COMMAND",
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:        runner.FlagType,
					Aliases:     []string{"t"},
					Usage:       "the run type",
					DefaultText: string(runner.TypeSeccomp),
				},
				&cli.StringFlag{
					Name:      runner.FlagProfile,
					Aliases:   []string{"p"},
					Usage:     "the profile to be used",
					Required:  true,
					TakesFile: true,
				},
			},
		},
	)

	if err := app.Run(os.Args); err != nil {
		log.Fatalf("Unable to run: %v", err)
	}
}

// record runs the `spoc record` subcommand.
func record(ctx *cli.Context) error {
	options, err := recorder.FromContext(ctx)
	if err != nil {
		return fmt.Errorf("build options: %w", err)
	}

	if err := recorder.New(options).Run(); err != nil {
		return fmt.Errorf("run recorder: %w", err)
	}

	return nil
}

// run runs the `spoc run` subcommand.
func run(ctx *cli.Context) error {
	options, err := runner.FromContext(ctx)
	if err != nil {
		return fmt.Errorf("build options: %w", err)
	}

	if err := runner.New(options).Run(); err != nil {
		return fmt.Errorf("launch runner: %w", err)
	}

	return nil
}
