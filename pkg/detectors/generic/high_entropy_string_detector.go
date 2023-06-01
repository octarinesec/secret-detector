package generic

import (
	"math"
	"regexp"
	"strconv"
	"strings"

	"gitlab.bit9.local/octarine/detect-secrets/pkg/detectors/helpers"
	"gitlab.bit9.local/octarine/detect-secrets/pkg/secrets"
)

const (
	HighEntropyStringDetectorName       = "high_entropy_string"
	highEntropyStringDetectorSecretType = "High entropy string"

	// hexEntropyThreshold and base64EntropyThreshold are magic numbers that were selected by trial & error.
	// A low threshold might cause more false positive detections.
	// A high threshold might cause more missed detections (false negative).
	// We'll might want to change those numbers in the future according to results in production.
	//
	// min possible entropy level = all characters are similar = 0
	// max possible entropy level = log2(len(charset))
	//   hex max    = log2(16) = 4.0
	//   base64 max = log2(64) = 6.0
	hexEntropyThreshold    = 3.0
	base64EntropyThreshold = 4.0

	// base64Regex represents a regex that matches a valid base64 string.
	// The minimum length allowed is 16 characters, not including padding.
	//
	// Note: this regex will also catch hexadecimal strings, since it is a subset of base64.
	base64Regex = `(?:[a-zA-Z0-9+/]{16,}|[a-zA-Z0-9_-]{16,})={0,2}`

	// hexExactRegex represents a regex that matches a valid hexadecimal string, with optional '0x' prefix.
	hexExactRegex = `^(?:0x)?[0-9a-f]+$`
)

func init() {
	secrets.GetDetectorFactory().Register(HighEntropyStringDetectorName, NewHighEntropyStringDetector)
}

type highEntropyStringDetector struct {
	secrets.Detector
	hexRegex *regexp.Regexp
}

func NewHighEntropyStringDetector() secrets.Detector {
	d := &highEntropyStringDetector{}
	d.hexRegex = regexp.MustCompile(hexExactRegex)
	d.Detector = helpers.NewRegexDetectorWithVerifier(d.isHighEntropyString, highEntropyStringDetectorSecretType, base64Regex)
	return d
}

func (d *highEntropyStringDetector) isHighEntropyString(s string) bool {
	// ignore digit only strings
	if isNumeric(s) {
		return false
	}

	s = strings.TrimRight(s, "=")
	entropyThreshold := base64EntropyThreshold
	if d.isHexadecimal(s) {
		entropyThreshold = hexEntropyThreshold
	}
	return calcShannonEntropy(s) > entropyThreshold
}

func (d *highEntropyStringDetector) isHexadecimal(s string) bool {
	return d.hexRegex.MatchString(s)
}

// calcShannonEntropy calculates how random a string is.
// Minimal possible level is 0, which means that all characters in the string are similar.
// Maximal possible level is log2(len(s)), which means that all characters in the string are different from one another.
//
// Formula: sum( frequency(char) * log2(frequency(char)) )
// See more https://en.wikipedia.org/wiki/Entropy_(information_theory)
func calcShannonEntropy(s string) float64 {
	length := float64(len(s))
	charCounts := make(map[rune]float64)
	for _, c := range s {
		charCounts[c]++
	}

	var sumFrequencies float64
	for _, count := range charCounts {
		f := count / length
		sumFrequencies += -f * math.Log2(f)
	}
	return sumFrequencies
}

func isNumeric(s string) bool {
	_, err := strconv.ParseFloat(s, 64)
	return err == nil
}
