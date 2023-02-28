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

	"github.com/urfave/cli/v2"

	"sigs.k8s.io/security-profiles-operator/cmd"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/cli/recorder"
)

func main() {
	app, _ := cmd.DefaultApp()
	app.Usage = "Security Profiles Operator CLI"

	app.Commands = append(app.Commands,
		&cli.Command{
			Name:      "record",
			Aliases:   []string{"r"},
			Usage:     "run the recorder",
			Action:    runRecord,
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
			},
		},
	)

	if err := app.Run(os.Args); err != nil {
		log.Fatalf("Unable to run: %v", err)
	}
}

// runRecord runs the `spoc record` subcommand.
func runRecord(ctx *cli.Context) error {
	options, err := recorder.FromContext(ctx)
	if err != nil {
		return fmt.Errorf("build options: %w", err)
	}

	if err := recorder.New(options).Run(); err != nil {
		return fmt.Errorf("run recorder: %w", err)
	}

	return nil
}
