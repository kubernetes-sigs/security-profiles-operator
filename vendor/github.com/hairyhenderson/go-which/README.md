# go-which

[![Build Status][circleci-image]][circleci-url]
[![hairyhenderson/go-which on DockerHub][dockerhub-image]][dockerhub-url]
[![GoDoc][godoc-image]][godocs]

A cross-platform Go implementation of the `which(1)` command, usable both as a CLI and library.

```console
Usage of which:
  -a    List all instances of executables found (instead of just the first).
  -s    No output, just return 0 if all executables are found, or 1 if some were not found.
  -v    Print the version
```

Unlike the UNIX `which(1)` command, even if multiple programs are given as input, only the first one found will be returned.

## CLI Usage

Chances are you don't really need this, since most UNIX-like OSes come with the more established (and significantly smaller) C implementation of `which(1)`, either as a standalone binary, or as a shell builtin.

_But_ if there's some reason this may be useful to you, you can use this just like the normal `which(1)`:

```console
$ which zsh
/usr/local/bin/zsh
$ which -a zsh
/usr/local/bin/zsh
/bin/zsh
```

```console
$ which zsh bash sh
/usr/local/bin/zsh
$ which -a zsh bash sh
/usr/local/bin/zsh
/bin/zsh
/bin/bash
/bin/sh
```

```console
$ if (which -s zsh bash); then
> echo 'I have zsh and bash installed';
> fi
I have zsh and bash installed
$ if (which -s zsh bash ash); then echo 'yup'
> else
> echo "I'm missing one of them...";
> fi
I'm missing one of them...
```

## Go package usage

If you're writing a program in the Go language, it can be useful to not have to shell out to `which(1)` to locate a binary.

The simplest usage is:

```go
package main

import (
  "fmt"
  "github.com/hairyhenderson/go-which"
)

func main() {
  zshPath := which.Which("zsh")

  fmt.Printf("zsh found at %s", zshPath)
}
```

See the [godocs][] for more information.

## License

[The MIT License](http://opensource.org/licenses/MIT)

Copyright (c) 2018-2020 Dave Henderson

[godocs]: https://pkg.go.dev/github.com/hairyhenderson/go-which

[circleci-image]: https://circleci.com/gh/hairyhenderson/go-which/tree/master.svg?style=shield
[circleci-url]: https://circleci.com/gh/hairyhenderson/go-which/tree/master
[dockerhub-image]: https://img.shields.io/badge/docker-ready-blue.svg
[dockerhub-url]: https://hub.docker.com/r/hairyhenderson/go-which
[godoc-image]: https://godoc.org/github.com/hairyhenderson/go-which?status.svg
