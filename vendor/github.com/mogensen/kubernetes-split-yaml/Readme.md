# kubernetes-split-yaml

[![Build Status](https://img.shields.io/endpoint.svg?url=https%3A%2F%2Factions-badge.atrox.dev%2Fmogensen%2Fkubernetes-split-yaml%2Fbadge%3Fref%3Dmaster&style=flat)](https://actions-badge.atrox.dev/mogensen/kubernetes-split-yaml/goto?ref=master)
[![Go Report Card](https://goreportcard.com/badge/github.com/mogensen/kubernetes-split-yaml)](https://goreportcard.com/report/github.com/mogensen/kubernetes-split-yaml)
[![codecov](https://codecov.io/gh/mogensen/kubernetes-split-yaml/branch/master/graph/badge.svg)](https://codecov.io/gh/mogensen/kubernetes-split-yaml)
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fmogensen%2Fkubernetes-split-yaml.svg?type=shield)](https://app.fossa.com/projects/git%2Bgithub.com%2Fmogensen%2Fkubernetes-split-yaml?ref=badge_shield)

Split the 'giant yaml file' into one file pr kubernetes resource

## Installation

If you have golang installed you can use `go get`.

```bash
$ go get -v github.com/mogensen/kubernetes-split-yaml
```
This will download the source and install the binary `kubernetes-split-yaml`

## Usage

* Simple invocation

```
$ kubernetes-split-yaml giant-k8s-file.yaml
```

* Modify / filter output filenames

```
# Note by default it'll output 0.2.0 non-hierical files
$ kubernetes-split-yaml --help

# Get namespaced hierarchy for output files
$ kubernetes-split-yaml --template_sel tpl_ns --outdir my-clustername/namespaces giant-k8s-file.yaml

# Ditto above, but only for Kubernetes objects starting with "myapp"
$ kubernetes-split-yaml --name_re ^myapp --template_sel tpl_ns --outdir my-clustername/namespaces giant-k8s-file.yaml

# Ditto above, but only for Deployments and StatefulSets
$ kubernetes-split-yaml --kind_re '^(StatefulSet|Deployment)' --name_re ^myapp --template_sel tpl_ns --outdir my-clustername/namespaces giant-k8s-file.yaml
```


## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Please make sure to update tests as appropriate.

## License
[MIT](https://choosealicense.com/licenses/mit/)


[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fmogensen%2Fkubernetes-split-yaml.svg?type=large)](https://app.fossa.com/projects/git%2Bgithub.com%2Fmogensen%2Fkubernetes-split-yaml?ref=badge_large)