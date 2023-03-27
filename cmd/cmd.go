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

package cmd

import (
	"fmt"
	"log"

	"github.com/urfave/cli/v2"

	"sigs.k8s.io/security-profiles-operator/internal/pkg/version"
)

const jsonFlag string = "json"

func DefaultApp() (*cli.App, *version.Info) {
	app := cli.NewApp()

	info, err := version.Get()
	if err != nil {
		log.Fatal(err)
	}
	app.Version = info.Version

	app.Commands = cli.Commands{
		&cli.Command{
			Name:    "version",
			Aliases: []string{"v"},
			Usage:   "display detailed version information",
			Flags: []cli.Flag{
				&cli.BoolFlag{
					Name:    jsonFlag,
					Aliases: []string{"j"},
					Usage:   "print JSON instead of text",
				},
			},
			Action: func(c *cli.Context) error {
				res := info.String()
				if c.Bool(jsonFlag) {
					j, err := info.JSONString()
					if err != nil {
						return fmt.Errorf("unable to generate JSON from version info: %w", err)
					}
					res = j
				}
				print(res)
				return nil
			},
		},
	}

	return app, info
}
