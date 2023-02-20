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
	"log"
	"os"

	"github.com/urfave/cli/v2"

	"sigs.k8s.io/security-profiles-operator/cmd"
)

func main() {
	app, _ := cmd.DefaultApp()
	app.Usage = "Security Profiles Operator CLI"

	app.Commands = append(app.Commands,
		&cli.Command{
			Name:    "record",
			Aliases: []string{"r"},
			Usage:   "run the recorder",
			Action:  record,
		},
	)

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}
