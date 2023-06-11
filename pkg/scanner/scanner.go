package scanner

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/hashicorp/go-multierror"

	"github.com/octarinesec/secret-detector/pkg/dataformat"
	"github.com/octarinesec/secret-detector/pkg/secrets"
)

const (
	SizeThresholdViolationType = "Suspicious text file size"
)

type scanner struct {
	detectors         []secrets.Detector
	filesTransformers []secrets.Transformer
	thresholdInBytes  int64

	transformersByFormat map[dataformat.DataFormat][]secrets.Transformer
}

func NewScannerFromConfig(config Config) (secrets.Scanner, error) {
	supportedTransformers, missingT := secrets.GetTransformerFactory().Create(config.Transformers)
	supportedDetectors, missingD := secrets.GetDetectorFactory().Create(config.Detectors, config.DetectorConfigs)

	var err error
	if len(missingT) > 0 || len(missingD) > 0 {
		err = fmt.Errorf("some plugins were unable to load: missing_transformers=%v, missing_detectors=%v", missingT, missingD)
	}

	return NewScanner(supportedTransformers, supportedDetectors, config.ThresholdInBytes), err
}

func NewDefaultScanner() secrets.Scanner {
	s, _ := NewScannerFromConfig(NewConfigWithDefaults())
	return s
}

func NewEmptyScanner() secrets.Scanner {
	return NewScanner(nil, nil, -1)
}

func NewScanner(transformers []secrets.Transformer, detectors []secrets.Detector, thresholdInBytes int) secrets.Scanner {
	transformersMap := make(map[dataformat.DataFormat][]secrets.Transformer)
	filesTransformers := make([]secrets.Transformer, 0, len(transformers))

	for _, transformer := range transformers {
		for _, format := range transformer.SupportedFormats() {
			transformersMap[format] = append(transformersMap[format], transformer)
		}
		if transformer.SupportFiles() {
			filesTransformers = append(filesTransformers, transformer)
		}
	}

	return &scanner{
		filesTransformers:    filesTransformers,
		detectors:            detectors,
		thresholdInBytes:     int64(thresholdInBytes),
		transformersByFormat: transformersMap,
	}
}

// ScanFile scans a file found in path for secrets.
//
// returned errors can be distinguished using:
//
//	err.(*secrets.NotTextFileError)
//	errors.Is(err, os.ErrNotExist)
//	errors.Is(err, os.ErrPermission)
//	errors.Is(err, os.ErrClosed)
func (s *scanner) ScanFile(path string) ([]secrets.DetectedSecret, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	if !isTextFile(f) {
		return nil, secrets.NewNotTextFileError(path)
	}

	stat, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !s.validateThreshold(stat.Size()) {
		return []secrets.DetectedSecret{{Type: SizeThresholdViolationType, Key: path}}, nil
	}

	return s.ScanWithFormat(f, dataformat.FromPath(path))
}

func (s *scanner) ScanFileReader(in io.Reader, path string, size int64) ([]secrets.DetectedSecret, error) {
	inStr, err := readerToString(in)
	if err != nil {
		return nil, err
	}

	if !isTextString(inStr) {
		return nil, secrets.NewNotTextFileError(path)
	}

	if !s.validateThreshold(size) {
		return []secrets.DetectedSecret{{Type: SizeThresholdViolationType, Key: path}}, nil
	}

	return s.ScanStringWithFormat(inStr, dataformat.FromPath(path))
}

func (s *scanner) ScanWithFormat(in io.Reader, format dataformat.DataFormat) ([]secrets.DetectedSecret, error) {
	inStr, err := readerToString(in)
	if err != nil {
		return nil, err
	}

	transformers := s.transformersByFormat[format]
	if len(transformers) == 0 {
		transformers = s.filesTransformers
	}

	return s.scan(inStr, transformers)
}

func (s *scanner) ScanStringWithFormat(inStr string, format dataformat.DataFormat) ([]secrets.DetectedSecret, error) {
	transformers := s.transformersByFormat[format]
	if len(transformers) == 0 {
		transformers = s.filesTransformers
	}

	return s.scan(inStr, transformers)
}

func (s *scanner) ScanReader(in io.Reader) ([]secrets.DetectedSecret, error) {
	inStr, err := readerToString(in)
	if err != nil {
		return nil, err
	}

	return s.Scan(inStr)
}

func (s *scanner) Scan(in string) ([]secrets.DetectedSecret, error) {
	return s.scan(in, s.filesTransformers)
}

func (s *scanner) scan(in string, transformers []secrets.Transformer) (res []secrets.DetectedSecret, err error) {
	in = strings.TrimSpace(in)
	if len(in) == 0 {
		return
	}

	// a file that exceeds the threshold size is considered as a suspicious file, so a detection is returned
	if !s.validateThreshold(int64(len(in))) {
		return []secrets.DetectedSecret{{Type: SizeThresholdViolationType}}, nil
	}

	if keyValueMap, isTransformed := transform(in, transformers); isTransformed {
		res, err = s.scanMap(keyValueMap)
	} else {
		res, err = s.scanString(in)
	}
	res = reduceDuplicateDetections(res)

	return
}

func (s *scanner) scanString(in string) (res []secrets.DetectedSecret, err error) {
	isMultiline := strings.ContainsRune(in, '\n')
	for _, detector := range s.detectors {
		// notice that a detector can return both results and an error
		detectedSecrets, currErr := detector.Scan(in)
		if currErr != nil {
			err = multierror.Append(currErr)
		}
		res = append(res, detectedSecrets...)

		// if input is one liner break on first detection (no point of finding multiple detections on the same input)
		if !isMultiline && len(res) > 0 {
			break
		}
	}
	return
}

func (s *scanner) scanMap(keyValueMap map[string]string) (res []secrets.DetectedSecret, err error) {
	for _, detector := range s.detectors {
		// notice that a detector can return both results and an error
		detectedSecrets, currErr := detector.ScanMap(keyValueMap)
		if currErr != nil {
			err = multierror.Append(currErr)
		}
		res = append(res, detectedSecrets...)
	}
	return
}

func (s *scanner) validateThreshold(length int64) bool {
	return length <= s.thresholdInBytes || s.thresholdInBytes <= 0
}

func transform(in string, transformers []secrets.Transformer) (map[string]string, bool) {
	for _, transformer := range transformers {
		if result, ok := transformer.Transform(in); ok {
			return result, ok
		}
	}
	return nil, false
}

func readerToString(in io.Reader) (string, error) {
	b, err := io.ReadAll(in)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// reduceDuplicateDetections remove detections with the same key and leaves only the first one.
// This could happen in cases when the same value is caught by multiple detectors.
// e.g. azure key might also be a high entropy base64.
func reduceDuplicateDetections(detections []secrets.DetectedSecret) []secrets.DetectedSecret {
	res := make([]secrets.DetectedSecret, 0, len(detections))
	m := make(map[string]bool)
	for _, detection := range detections {
		if detection.Key == "" {
			res = append(res, detection)
			continue
		}

		if !m[detection.Key] {
			m[detection.Key] = true
			res = append(res, detection)
		}
	}
	return res
}
