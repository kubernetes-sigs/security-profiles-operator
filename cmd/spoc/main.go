/*
Copyright The Kubernetes Authors.

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
	"errors"
	"fmt"
	"log"
	"os"

	"github.com/go-logr/logr"
	"github.com/urfave/cli/v2"

	"sigs.k8s.io/security-profiles-operator/cmd"
	spocli "sigs.k8s.io/security-profiles-operator/internal/pkg/cli"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/cli/command"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/cli/converter"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/cli/installer"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/cli/merger"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/cli/puller"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/cli/pusher"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/cli/recorder"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/cli/remover"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/cli/runner"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/cli/signer"
	"sigs.k8s.io/security-profiles-operator/internal/pkg/util/clidocs"
)

// exitCodeBaseProfileOutdated is the exit code of `spoc merge --check` when
// the first profile is not a superset of the others. It is the generic
// failure exit code, which scripts rely on. The log tells an outdated base
// profile ("Base profile needs an update.") apart from a failure ("Unable to
// run: ...").
const exitCodeBaseProfileOutdated = 1

func main() {
	// spoc run re-executes itself to confine the command, which has to
	// happen before anything else.
	runner.Init()

	log.SetFlags(log.Lmicroseconds)

	if err := newApp().Run(os.Args); err != nil {
		log.Fatalf("Unable to run: %v", err)
	}
}

// runtimeEnvVars are the environment variables spoc reads which are not
// bound to a flag.
var runtimeEnvVars = []clidocs.EnvVar{
	{
		Name: spocli.EnvKeyUsername,
		Description: "username for the registry authentication of push, pull and sign " +
			"if the flag is not set",
	},
	{
		Name:        spocli.EnvKeyPassword,
		Description: "password for the registry authentication of push, pull and sign",
	},
	{
		Name:        spocli.EnvKeyUsernameDeprecated,
		Description: "deprecated, use `" + spocli.EnvKeyUsername + "`",
	},
	{
		Name:        spocli.EnvKeyPasswordDeprecated,
		Description: "deprecated, use `" + spocli.EnvKeyPassword + "`",
	},
	{
		Name: "SUDO_UID, SUDO_GID, SUDO_USER",
		Description: "set by sudo, used by record and run to drop the privileges " +
			"of the target command to the invoking user",
	},
	{
		Name: "TUF_ROOT, TUF_MIRROR, TUF_ROOT_JSON",
		Description: "the TUF cache directory, mirror and trust anchor of the Sigstore " +
			"trusted root and signing config used by push, pull and sign, as for cosign",
	},
	{
		Name: "SIGSTORE_ID_TOKEN",
		Description: "OIDC identity token for keyless signing on push and sign, " +
			"an empty value counts as unset",
	},
	{
		Name: "ACTIONS_ID_TOKEN_REQUEST_URL, ACTIONS_ID_TOKEN_REQUEST_TOKEN",
		Description: "set by GitHub Actions for jobs with the `id-token: write` permission, " +
			"used to get the OIDC identity token for keyless signing on push and sign",
	},
	{
		Name: "SOURCE_DATE_EPOCH",
		Description: "seconds since the Unix epoch for the `org.opencontainers.image.created` " +
			"annotation of push, which defaults to `1970-01-01T00:00:00Z`",
	},
}

func newApp() *cli.App {
	app, _ := cmd.DefaultApp()
	app.Name = "spoc"
	app.Usage = "Security Profiles Operator CLI"

	app.Commands = append(app.Commands,
		clidocs.Command(newApp, runtimeEnvVars),
		&cli.Command{
			Name:    "record",
			Aliases: []string{"r"},
			Usage:   "run a command and record the security profile",
			Description: "Run a command and record the security profile of what it did. " +
				"The profile is written even if the command fails, and spoc record exits " +
				"with 0 then, so that a crashing workload can still be profiled.",
			Action:    record,
			ArgsUsage: "COMMAND",
			Flags:     recorder.Flags(),
		},
		&cli.Command{
			Name:    "merge",
			Aliases: []string{"m"},
			Usage:   "merge multiple security profiles",
			Description: "Merge multiple security profiles into a combined profile. " +
				"Permissions are additive. For AppArmor, the first profile may additionally contain glob paths.",
			Action:    merge,
			ArgsUsage: "PROFILE...",
			Flags:     merger.Flags(),
		},
		&cli.Command{
			Name:    "convert",
			Aliases: []string{"c"},
			Usage:   "convert a security profile to its raw format",
			Description: "Convert a SeccompProfile CRD into a raw OCI runtime-spec seccomp " +
				"profile in JSON, or an AppArmorProfile CRD into a raw AppArmor profile. " +
				"The raw profile is written to stdout unless --output-file is set.",
			Action:    convert,
			ArgsUsage: "PROFILE",
			Flags:     converter.Flags(),
		},
		&cli.Command{
			Name:    "install",
			Aliases: []string{"i"},
			Usage:   "install an AppArmor profile on the local machine",
			Description: "Load the AppArmorProfile CRD of PROFILE (default: " + installer.DefaultProfileFile +
				") into the kernel. The profile confines EXECUTABLE, which becomes its name. " +
				"Without it, a profile name which is a command on the PATH is resolved to its " +
				"executable. Other profile kinds are rejected. Requires root on a host with " +
				"AppArmor enabled.",
			Action:    install,
			ArgsUsage: "[PROFILE [EXECUTABLE]]",
		},
		&cli.Command{
			Name:    "remove",
			Aliases: []string{"rm"},
			Usage:   "remove an AppArmor profile from the local machine",
			Description: "Unload the AppArmorProfile CRD of PROFILE (default: " + installer.DefaultProfileFile +
				") from the kernel. The profile name is derived like on install, so pass the " +
				"same EXECUTABLE. Requires root on a host with AppArmor enabled.",
			Action:    remove,
			ArgsUsage: "[PROFILE [EXECUTABLE]]",
		},
		&cli.Command{
			Name:    "run",
			Aliases: []string{"x"},
			Usage:   "run a command using a seccomp profile",
			Description: "Run a command confined by the seccomp profile of --profile, and print " +
				"the denials found in the audit log. spoc exits with the exit code of the command.",
			Action:    run,
			ArgsUsage: "COMMAND",
			Flags:     runner.Flags(),
		},
		&cli.Command{
			Name:    "push",
			Aliases: []string{"p"},
			Usage:   "push profiles to a container registry",
			Description: "Push the profiles of --profiles to IMAGE. " +
				"Profile CRDs are pushed as YAML artifacts for oci:// base profiles. " +
				"A raw OCI runtime-spec seccomp profile in JSON is pushed in the KEP-6061 " +
				"runtime format for container runtimes (single JSON layer, media type " +
				"application/vnd.cncf.seccomp-profile.config.v1+json); exactly one profile " +
				"is allowed in that format.",
			Action:    push,
			ArgsUsage: "IMAGE",
			Flags:     pusher.Flags(),
		},
		&cli.Command{
			Name:    "pull",
			Aliases: []string{"l"},
			Usage:   "pull a profile from a container registry",
			Description: "Pull the profile of IMAGE, verifying its signature by default. " +
				"Profile CRD artifacts and KEP-6061 runtime format artifacts are " +
				"supported; the artifact content is written unchanged, so runtime format " +
				"artifacts are saved as runtime-spec JSON and the default output file " +
				"switches to a .json extension.",
			Action:    pull,
			ArgsUsage: "IMAGE",
			Flags:     puller.Flags(),
		},
		&cli.Command{
			Name:  "sign",
			Usage: "sign an artifact in a container registry",
			Description: "Sign an artifact keyless like spoc push does, for example one " +
				"whose signing failed after the push. A tag is resolved to its digest, " +
				"which the signature is about.",
			Action:    sign,
			ArgsUsage: "IMAGE",
			Flags:     signer.Flags(),
		},
	)

	return app
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

// merge runs the `spoc merge` subcommand.
func merge(ctx *cli.Context) error {
	options, err := merger.FromContext(ctx)
	if err != nil {
		return fmt.Errorf("build options: %w", err)
	}

	if err := merger.New(options).Run(); err != nil {
		return mergeError(err)
	}

	return nil
}

// mergeError maps the error of the merger onto the exit code of `spoc
// merge`. In check mode an outdated base profile is a result, not a failure,
// so it is reported through its own exit code only.
func mergeError(err error) error {
	if errors.Is(err, merger.ErrBaseProfileOutdated) {
		return cli.Exit("", exitCodeBaseProfileOutdated)
	}

	return fmt.Errorf("launch merger: %w", err)
}

// convert runs the `spoc convert` subcommand.
func convert(ctx *cli.Context) error {
	options, err := converter.FromContext(ctx)
	if err != nil {
		return fmt.Errorf("build options: %w", err)
	}

	if err := converter.New(options).Run(); err != nil {
		return fmt.Errorf("launch converter: %w", err)
	}

	return nil
}

// install runs the `spoc install` subcommand.
func install(ctx *cli.Context) error {
	options, err := installer.FromContext(ctx)
	if err != nil {
		return fmt.Errorf("build options: %w", err)
	}

	if err := installer.New(options, logr.New(&spocli.LogSink{})).Run(); err != nil {
		return fmt.Errorf("launch installer: %w", err)
	}

	return nil
}

// remove runs the `spoc remove` subcommand.
func remove(ctx *cli.Context) error {
	options, err := installer.FromContext(ctx)
	if err != nil {
		return fmt.Errorf("build options: %w", err)
	}

	if err := remover.New(options, logr.New(&spocli.LogSink{})).Run(); err != nil {
		return fmt.Errorf("launch profile remover: %w", err)
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
		// Pass the exit code of the command on, like a shell does.
		if code, exited := command.ExitCode(err); exited {
			log.Printf("Command failed: %v", err)

			return cli.Exit("", code)
		}

		return fmt.Errorf("launch runner: %w", err)
	}

	return nil
}

// push runs the `spoc push` subcommand.
func push(ctx *cli.Context) error {
	options, err := pusher.FromContext(ctx)
	if err != nil {
		return fmt.Errorf("build options: %w", err)
	}

	if err := pusher.New(options).Run(); err != nil {
		return fmt.Errorf("run pusher: %w", err)
	}

	return nil
}

// sign runs the `spoc sign` subcommand.
func sign(ctx *cli.Context) error {
	options, err := signer.FromContext(ctx)
	if err != nil {
		return fmt.Errorf("build options: %w", err)
	}

	if err := signer.New(options).Run(); err != nil {
		return fmt.Errorf("run signer: %w", err)
	}

	return nil
}

// pull runs the `spoc pull` subcommand.
func pull(ctx *cli.Context) error {
	options, err := puller.FromContext(ctx)
	if err != nil {
		return fmt.Errorf("build options: %w", err)
	}

	if err := puller.New(options).Run(); err != nil {
		return fmt.Errorf("run puller: %w", err)
	}

	return nil
}
