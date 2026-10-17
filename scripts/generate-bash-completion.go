// Command generate-bash-completion derives Bash completion from the CLI's offline help.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"regexp"
	"strings"
	"text/template"

	"github.com/perimeterd/perimeterd/internal/cli"
)

type command struct {
	Name    string
	Options []option
}

type option struct {
	Name       string
	TakesValue bool
	Files      bool
	Choices    string
}

func main() {
	output := flag.String("output", "bin/completions/perimeterd", "output file")
	flag.Parse()
	if err := generate(*output); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func help(args ...string) (string, error) {
	var stdout, stderr bytes.Buffer
	if code := cli.Run(args, &stdout, &stderr); code != 0 {
		return "", fmt.Errorf("read help for %v: exit %d: %s", args, code, stderr.String())
	}
	return stdout.String(), nil
}

func generate(output string) error {
	root, err := help("--help")
	if err != nil {
		return err
	}
	// Optional flags and their value vocabularies come from the same usage
	// signatures shown to users, including lookup's custom argument parser.
	optionalFlag := regexp.MustCompile(`\[--([a-z][a-z0-9-]*)(?: ([^\]]+))?\]`)
	var commands []command
	for line := range strings.SplitSeq(root, "\n") {
		words := strings.Fields(line)
		if len(words) < 2 || words[0] != "perimeterd" {
			continue
		}
		name := words[1]
		usage, err := help(name, "--help")
		if err != nil {
			return err
		}
		signature, _, _ := strings.Cut(usage, "\n")
		cmd := command{Name: name}
		for _, match := range optionalFlag.FindAllStringSubmatch(signature, -1) {
			opt := option{Name: match[1], TakesValue: match[2] != "", Files: match[2] == "PATH"}
			if strings.Contains(match[2], "|") {
				opt.Choices = strings.ReplaceAll(match[2], "|", " ")
			}
			cmd.Options = append(cmd.Options, opt)
		}
		commands = append(commands, cmd)
	}
	if len(commands) == 0 {
		return fmt.Errorf("no commands found in perimeterd help")
	}
	tmpl, err := template.New("bash").Funcs(template.FuncMap{
		"quote": func(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'" },
	}).Parse(bashCompletion)
	if err != nil {
		return err
	}
	var script bytes.Buffer
	if err := tmpl.Execute(&script, commands); err != nil {
		return err
	}
	return os.WriteFile(output, script.Bytes(), 0o600)
}

const bashCompletion = `# Code generated from perimeterd's offline help; DO NOT EDIT.

_perimeterd()
{
    local cur prev command prefix='' kind='' choices='' index
    COMPREPLY=()
    cur=${COMP_WORDS[COMP_CWORD]}
    prev=${COMP_WORDS[COMP_CWORD-1]}

    if (( COMP_CWORD == 1 )); then
        mapfile -t COMPREPLY < <(compgen -W '{{range .}}{{.Name}} {{end}}help --help -h' -- "$cur")
        return 0
    fi
    command=${COMP_WORDS[1]}

    # Bash normally splits '=' into its own completion word. Also support
    # shells that have removed '=' from COMP_WORDBREAKS.
    if [[ $cur == = ]]; then
        cur=''
    elif [[ $cur == -*=* ]]; then
        prev=${cur%%=*}
        prefix=$prev=
        cur=${cur#*=}
    elif [[ $prev == = ]] && (( COMP_CWORD > 2 )); then
        prev=${COMP_WORDS[COMP_CWORD-2]}
    fi

    case "$command:$prev" in
{{- range . }}
{{- $command := .Name }}
{{- range .Options }}
{{- if .TakesValue }}
        {{$command}}:--{{.Name}}|{{$command}}:-{{.Name}})
            kind='{{if .Files}}file{{else}}value{{end}}'
            choices={{quote .Choices}}
            ;;
{{- end }}
{{- end }}
{{- end }}
    esac

    if [[ $kind == file ]]; then
        mapfile -t COMPREPLY < <(compgen -f -- "$cur")
        compopt -o filenames
    elif [[ $kind == value ]]; then
        if [[ -n $choices ]]; then
            mapfile -t COMPREPLY < <(compgen -W "$choices" -- "$cur")
        fi
    else
        case $command in
{{- range . }}
            {{.Name}})
                choices='{{range .Options}}--{{.Name}} {{end}}--help -h'
                ;;
{{- end }}
        esac
        if [[ -n $choices ]]; then
            mapfile -t COMPREPLY < <(compgen -W "$choices" -- "$cur")
        fi
    fi

    if [[ -n $prefix ]]; then
        for index in "${!COMPREPLY[@]}"; do
            COMPREPLY[index]=$prefix${COMPREPLY[index]}
        done
    fi
    return 0
}

complete -F _perimeterd perimeterd
`
