package main

import (
	"io/ioutil"
	"path/filepath"

	"bytes"
	"fmt"
	"os"
	"regexp"
	"strings"
	"text/template"

	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
)

var log = logrus.New()

// Some regexp defaults
const FileRe = ".+"

// NameRe must be less strict than e.g. NamespaceRe specially because of
// - non-namespaced like CRDs (they usually contain dots)
// - others like PSPs (containing `:`)
const NameRe = "^[^/ ]+$"
const KindRe = "^[0-9a-zA-Z]+$"

// NamespaceRe: empty or DNSre
const NamespaceRe = "^(|[a-z0-9]([-a-z0-9]*[a-z0-9])?)$"

// Flags defaults
var TemplateFlat = filepath.Join("{{.X.Outdir}}", "{{.Metadata.Name}}-{{.X.ShortKind}}.yaml")
var TemplateNS = filepath.Join("{{.X.Outdir}}", "{{.X.NS}}", "{{.Metadata.Name}}.{{.Kind}}.yaml")

// cli app flags
var appFlags = []cli.Flag{
	&cli.StringFlag{
		Name:  "outdir",
		Value: "generated",
		Usage: "output dir",
	},
	&cli.StringFlag{
		Name:  "template_sel",
		Value: "tpl_flat",
		Usage: "pre-set template to use",
	},
	&cli.StringFlag{
		Name:  "tpl_flat",
		Value: TemplateFlat,
		Usage: "tpl_flat gotemplate (.X.Outdir is set to `outdir` flag)",
	},
	&cli.StringFlag{
		Name:  "tpl_ns",
		Value: TemplateNS,
		Usage: "tpl_ns gotemplate (.X.NS equals .Metadata.Namespace or '_no_ns_' if unset)",
	},
	&cli.StringFlag{
		Name:  "name_re",
		Value: NameRe,
		Usage: "Kubernetes API metadata.name to match",
	},
	&cli.StringFlag{
		Name:  "namespace_re",
		Value: NamespaceRe,
		Usage: "Kubernetes API metadata.namespace to match",
	},
	&cli.StringFlag{
		Name:  "kind_re",
		Value: KindRe,
		Usage: "Kubernetes API kind to match",
	},
	&cli.StringFlag{
		Name:  "file_re",
		Value: FileRe,
		Usage: "final output file regex to match",
	},
}

type Filters struct {
	name      string
	namespace string
	kind      string
	filename  string
}

func main() {
	app := cli.NewApp()
	app.Name = "kubernetes-split-yaml"
	app.Usage = "Split the 'giant yaml file' into one file pr kubernetes resource"
	app.Flags = appFlags
	app.Action = func(c *cli.Context) error {

		outdir := c.String("outdir")
		templateSel := c.String("template_sel")
		outfileTemplate := c.String(templateSel)
		filters := &Filters{
			name:      c.String("name_re"),
			namespace: c.String("namespace_re"),
			kind:      c.String("kind_re"),
			filename:  c.String("file_re"),
		}

		handleFile(c.Args().Get(0), outdir, outfileTemplate, filters)
		return nil
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatalf("Error running: %v", err)
	}
}

func outFile(outdir string, t *template.Template, filters *Filters, m *KubernetesAPI) (string, error) {

	ns := m.Metadata.Namespace
	if ns == "" {
		ns = "_no_ns_"
	}

	// Setup  m.X. "extended" template-convienent fields
	m.X.Outdir = outdir
	m.X.NS = ns
	m.X.ShortKind = getShortName(m.Kind)

	buf := new(bytes.Buffer)
	err := t.Execute(buf, m)
	if err != nil {
		return "", fmt.Errorf("Failed to template.Execute on %v, verify template string", m)
	}
	filename := buf.String()

	regexps := []struct {
		str   string
		match string
		warn  bool
	}{
		// Note: we still keep the KindRe, NameRe, NamespaceRe default REs
		// for *sanity* verification, to avoid tricks like setting namespace to
		// "../../etc"
		{str: m.Kind, match: KindRe, warn: true},
		{str: m.Kind, match: filters.kind},
		{str: m.Metadata.Name, match: NameRe, warn: true},
		{str: m.Metadata.Name, match: filters.name},
		{str: m.Metadata.Namespace, match: NamespaceRe, warn: true},
		{str: m.Metadata.Namespace, match: filters.namespace},
		{str: filename, match: filters.filename},
	}
	for _, re := range regexps {
		matched, err := regexp.Match(re.match, []byte(re.str))
		if err != nil {
			log.Fatalf("Failed to match regexp '%s'", re.match)
		}
		if !matched {
			if re.warn {
				log.Warnf("Skipped suspicious object with kind='%s' namespace='%s' name='%s'",
					m.Kind, m.Metadata.Namespace, m.Metadata.Name)
			}
			return "", nil
		}
	}

	return filename, nil
}

func handleFile(file, outdir, outfileTemplate string, filters *Filters) {

	tpl, err := template.New("outfile").Parse(outfileTemplate)
	if err != nil {
		log.Fatalf("Failed create template from '%s'", outfileTemplate)
	}

	files := readAndSplitFile(file)

	for _, fileContent := range files {

		m, err := getYamlInfo(fileContent)
		if err != nil {
			log.Warnf("Ignoring %v", err)
			continue
		}

		filename, err := outFile(outdir, tpl, filters, m)
		if err != nil {
			log.Fatalf("Failed on outFile: %v", err)
		}
		if filename == "" {
			continue
		}

		log.Infof("Creating file: %s", filename)
		fileDir := filepath.Dir(filename)
		err = os.MkdirAll(fileDir, os.ModePerm)
		if err != nil {
			log.Fatalf("Failed to create directory '%s'", fileDir)
		}

		err = ioutil.WriteFile(filename, []byte(fileContent), os.ModePerm)
		if err != nil {
			log.Fatalf("Failed creating file %s : %v", filename, err)
		}
	}
}

func readAndSplitFile(file string) []string {
	var fileContent []byte
	if file == "-" {
		c, err := ioutil.ReadAll(os.Stdin)
		fileContent = c
		if err != nil {
			log.Fatalf("Failed reading from stdin: %v", err)
		}
	} else {
		c, err := ioutil.ReadFile(file)
		fileContent = c
		if err != nil {
			log.Fatalf("Failed reading file %s : %v", file, err)
		}
	}

	docs := strings.Split(string(fileContent), "\n---")

	res := []string{}
	// Trim whitespace in both ends of each yaml docs.
	// - Re-add a single newline last
	for _, doc := range docs {
		content := strings.TrimSpace(doc)
		// Ignore empty docs
		if content != "" {
			res = append(res, content+LineBreak)
		}
	}
	return res
}
