package download

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

var (
	numRangeRegex   = regexp.MustCompile(`\[(\d+)-(\d+)\]`)
	alphaRangeRegex = regexp.MustCompile(`\[([a-zA-Z])-([a-zA-Z])\]`)
)

// ExpandBatchLinks parses an input string that may contain multiple links or range patterns.
func ExpandBatchLinks(input string) ([]string, error) {
	trimmed := strings.TrimSpace(input)
	if trimmed == "" {
		return nil, errors.New("empty input")
	}

	// Split by newlines first
	lines := strings.Split(trimmed, "\n")
	var candidateTokens []string

	for _, line := range lines {
		l := strings.TrimSpace(line)
		if l == "" {
			continue
		}
		// If line has multiple URLs separated by whitespace
		parts := strings.Fields(l)
		candidateTokens = append(candidateTokens, parts...)
	}

	var results []string
	const maxBatchSize = 100

	for _, token := range candidateTokens {
		token = strings.TrimSpace(token)
		if token == "" {
			continue
		}

		expanded := expandPattern(token)
		for _, u := range expanded {
			if len(results) >= maxBatchSize {
				return results, fmt.Errorf("batch link expansion exceeded maximum limit of %d items", maxBatchSize)
			}
			norm := NormalizeLink(u)
			if norm != "" {
				results = append(results, norm)
			}
		}
	}

	if len(results) == 0 {
		return nil, errors.New("no valid download links found in input")
	}

	return results, nil
}

func expandPattern(raw string) []string {
	// 1. Numeric Range: [01-10] or [1-5]
	if match := numRangeRegex.FindStringSubmatchIndex(raw); match != nil {
		sStr := raw[match[2]:match[3]]
		eStr := raw[match[4]:match[5]]
		sVal, err1 := strconv.Atoi(sStr)
		eVal, err2 := strconv.Atoi(eStr)
		if err1 == nil && err2 == nil && sVal <= eVal && (eVal-sVal) < 100 {
			padZeroes := len(sStr) == len(eStr) && strings.HasPrefix(sStr, "0")
			width := len(sStr)
			var out []string
			prefix := raw[:match[0]]
			suffix := raw[match[1]:]

			for i := sVal; i <= eVal; i++ {
				var formatted string
				if padZeroes {
					formatted = fmt.Sprintf("%0*d", width, i)
				} else {
					formatted = strconv.Itoa(i)
				}
				sub := prefix + formatted + suffix
				// Recursively expand any subsequent range patterns
				out = append(out, expandPattern(sub)...)
			}
			return out
		}
	}

	// 2. Alphabetic Range: [a-d] or [A-D]
	if match := alphaRangeRegex.FindStringSubmatchIndex(raw); match != nil {
		sChar := raw[match[2]:match[3]][0]
		eChar := raw[match[4]:match[5]][0]
		if sChar <= eChar && (eChar-sChar) < 26 {
			var out []string
			prefix := raw[:match[0]]
			suffix := raw[match[1]:]

			for c := sChar; c <= eChar; c++ {
				sub := prefix + string(c) + suffix
				out = append(out, expandPattern(sub)...)
			}
			return out
		}
	}

	return []string{raw}
}
