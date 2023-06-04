package command

import (
	"fmt"
	"github.com/mattn/go-shellwords"
	"github.com/octarinesec/secret-detector/pkg/dataformat"
	"github.com/octarinesec/secret-detector/pkg/secrets"
	"strings"
)

const (
	Name = "command"
)

var supportedFormats = []dataformat.DataFormat{dataformat.Command}
var stopTokens = ";&|<>"

func init() {
	secrets.GetTransformerFactory().Register(Name, NewTransformer)
}

type transformer struct {
}

func NewTransformer() secrets.Transformer {
	return &transformer{}
}

func (t *transformer) SupportedFormats() []dataformat.DataFormat {
	return supportedFormats
}

func (t *transformer) SupportFiles() bool {
	return false
}

func isFlag(arg string) bool {
	return arg[0] == '-'
}

func cleanFlag(flag string) string {
	// clean -flag or --flag to flag
	if flag[0] == '-' {
		flag = flag[1:]
	}
	if flag[0] == '-' {
		flag = flag[1:]
	}
	return flag
}

func splitCommand(command string) ([][]string, error) {
	subCommands := make([][]string, 0)

	startPos := 0
	for startPos < len(command) {
		args, err := shellwords.Parse(command[startPos:])
		if err != nil {
			return nil, err
		}
		if len(args) == 0 {
			if i := strings.IndexAny(command[startPos:], stopTokens); i != -1 {
				startPos = startPos + i + 1 // skip the stop token and continue
				continue
			} else { // there aren't more sub commands to parse
				break
			}
		} else {
			subCommands = append(subCommands, args)
			if i := strings.Index(command[startPos:], args[len(args)-1]); i != -1 {
				startPos = startPos + i + len(args[len(args)-1]) + 1 // skip the parsed statement and continue
				continue
			} else { // error
				break
			}
		}
	}
	return subCommands, nil
}

func getCommandArgMap(args []string, id int) (map[string]string, bool) {
	argMap := make(map[string]string)

	nonFlagArgumentIndex := 0
	for i := 0; i < len(args); i++ {
		if isFlag(args[i]) {
			// parse the case of --key=value
			if equalsIndex := strings.Index(args[i], "="); equalsIndex != -1 {
				argMap[cleanFlag(args[i][:equalsIndex])] = args[i][equalsIndex+1:]
				continue
			}

			// parse the case of -key value or --key value
			// check that the next argument is not a flag
			if i != len(args)-1 && !isFlag(args[i+1]) {
				argMap[cleanFlag(args[i])] = args[i+1]
				i++
				continue
			}
		} else {
			// add arguments
			argMap[fmt.Sprintf("arg%d_%d", id, nonFlagArgumentIndex)] = args[i]
			nonFlagArgumentIndex++
		}
	}

	return argMap, true
}

func (t *transformer) Transform(in string) (map[string]string, bool) {
	subCommandsArgs, err := splitCommand(in)
	if err != nil {
		return nil, false
	}

	argMap := make(map[string]string)

	for i, subCommand := range subCommandsArgs {
		subArgMap, ok := getCommandArgMap(subCommand, i)
		if !ok {
			return nil, false
		}

		// unify the subcommands argMaps
		for key, value := range subArgMap {
			argMap[key] = value
		}
	}

	return argMap, true
}
