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
	"path/filepath"

	"github.com/urfave/cli/v2"

	"sigs.k8s.io/security-profiles-operator/cmd"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/cli/recorder"
)

const (
	outputFileFlag = "output-file"
	typeFlag       = "type"
	typeSeccomp    = "seccomp"
)

var defaultOutputFile = filepath.Join(os.TempDir(), "profile.yaml")

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
					Name:        outputFileFlag,
					Aliases:     []string{"o"},
					Usage:       "the output file path for the recorded profile",
					DefaultText: defaultOutputFile,
					TakesFile:   true,
				},
				&cli.StringFlag{
					Name:        typeFlag,
					Aliases:     []string{"t"},
					Usage:       "the record type",
					DefaultText: typeSeccomp,
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
	outputFile := defaultOutputFile
	if ctx.IsSet(outputFileFlag) {
		outputFile = ctx.String(outputFileFlag)
	}

	recordType := ctx.String(typeFlag)
	if ctx.IsSet(typeFlag) && recordType != typeSeccomp {
		return fmt.Errorf("unsupported record type %q", recordType)
	}

	if err := recorder.New().Run(outputFile, ctx.Args().Slice()...); err != nil {
		return fmt.Errorf("run recorder: %w", err)
	}

	return nil
}
