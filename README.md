# Detect secrets

This project it a rewrite of <https://github.com/Yelp/detect-secrets> in Go.

It is meant to be imported in other projects and uses as a Secret Detection Engine - given a piece of data, determine whether data contains a secret.

## How to use

In order to use it in another project, get the go module:

```shell
go get github.com/octarinesec/secret-detector
```

Then you can import it in your Go code and use it:

```go
import (
    "fmt"
    "io"
    "github.com/octarinesec/secret-detector/pkg/scanner"
)

func main() {
    scanner := scanner.NewDefaultScanner()
    
    // scanner input can be a file path 
    detectedSecrets, err := scanner.ScanFile("path/to/file")
    // or an io.Reader
    var in io.Reader
    detectedSecrets, err := scanner.ScanReader(in)
    // or just a simple string
    var secrets string
    detectedSecrets, err := scanner.Scan(secrets)
	
    // print the results
    for secret := range detectedSecrets {
        fmt.Printf("Secret of type '%s' found in '%s'\n", d.Type, d.Key)
    }  
}
```

## How it works

The tool has a plugin-based architecture. The `scanner.Scanner` has a collection of plugins, and it feeds the data to each plugin, combining the results.

There are two types of plugins:

### Transformer
```go
type Transformer interface {
    Transform(in string) (map[string]string, bool)
    SupportedFormats() []dataformat.DataFormat
    SupportFiles() bool
}
```
Transformer receives a `string` input and tries to convert it into a key-value `map[string]string`. Each transformer supports a different data structure, like `yamltransformer`, `jsontransformer`, etc. 

### Detector
```go
type Detector interface {
    Scan(in string) ([]DetectedSecret, error)
    ScanMap(keyValueMap map[string]string) ([]DetectedSecret, error)
    SecretType() string
}
```
Detector receives an input `string` or a key-value 'map[string]string', and will try to find secrets in it.

Each detector look for a different type of secret.
For example, `keyword.detector` checks for keywords like `password` or `api_key`.
`jwt.detector` checks whether a value is a valid JWT.

## Load Scanner using a config file
```go
import (
    "github.com/octarinesec/secret-detector/pkg/scanner"
)

func main() {
    // load config from json
    jsonCfg := `{
        "transformers": ["json", "yaml"], 
        "detectors": ["github", "jwt", "keyword"], 
        "threshold_in_bytes": 1000000}`
    cfg, err := scanner.NewConfigFromJson(strings.NewReader(jsonCfg))
    // or from yaml
    yamlCfg := "transformers:\n" +
        " - json\n" +
        " - yaml\n" +
        "detectors:\n" +
        " - github\n" +
        " - jwt\n" + 
        " - keyword\n" + 
        "threshold_in_bytes: 1000000"
    cfg, err := scanner.NewConfigFromYaml(strings.NewReader(yamlCfg))
	
	// create a scanner
    scanner := scanner.NewScannerFromConfig(cfg)
}
```