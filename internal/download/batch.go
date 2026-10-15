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

const (
	maxBatchSize    = 100
	maxPatternDepth = 3
)

// validatePatternComplexity calculates projected combinations before recursive expansion
// to prevent denial-of-service and combinatorial explosion attacks.
func validatePatternComplexity(raw string, remainingLimit int) error {
	numMatches := numRangeRegex.FindAllStringSubmatch(raw, -1)
	alphaMatches := alphaRangeRegex.FindAllStringSubmatch(raw, -1)
	totalPatterns := len(numMatches) + len(alphaMatches)
	if totalPatterns > maxPatternDepth {
		return fmt.Errorf("batch link pattern exceeds maximum nesting depth of %d patterns", maxPatternDepth)
	}

	product := 1
	for _, m := range numMatches {
		sVal, _ := strconv.Atoi(m[1])
		eVal, _ := strconv.Atoi(m[2])
		if sVal <= eVal {
			diff := eVal - sVal + 1
			product *= diff
			if product > remainingLimit {
				return fmt.Errorf("batch link pattern expansion exceeds maximum limit of %d items", maxBatchSize)
			}
		}
	}
	for _, m := range alphaMatches {
		sChar := m[1][0]
		eChar := m[2][0]
		if sChar <= eChar {
			diff := int(eChar - sChar + 1)
			product *= diff
			if product > remainingLimit {
				return fmt.Errorf("batch link pattern expansion exceeds maximum limit of %d items", maxBatchSize)
			}
		}
	}
	return nil
}

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

	for _, token := range candidateTokens {
		token = strings.TrimSpace(token)
		if token == "" {
			continue
		}

		remaining := maxBatchSize - len(results)
		if remaining <= 0 {
			return results, fmt.Errorf("batch link expansion exceeded maximum limit of %d items", maxBatchSize)
		}

		if err := validatePatternComplexity(token, remaining); err != nil {
			return results, err
		}

		expanded := expandPattern(token, remaining, 0)
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

func expandPattern(raw string, maxItems int, depth int) []string {
	if depth >= maxPatternDepth || maxItems <= 0 {
		return []string{raw}
	}

	// 1. Numeric Range: [01-10] or [1-5]
	if match := numRangeRegex.FindStringSubmatchIndex(raw); match != nil {
		sStr := raw[match[2]:match[3]]
		eStr := raw[match[4]:match[5]]
		sVal, err1 := strconv.Atoi(sStr)
		eVal, err2 := strconv.Atoi(eStr)
		if err1 == nil && err2 == nil && sVal <= eVal && (eVal-sVal) < maxBatchSize {
			padZeroes := len(sStr) == len(eStr) && strings.HasPrefix(sStr, "0")
			width := len(sStr)
			var out []string
			prefix := raw[:match[0]]
			suffix := raw[match[1]:]

			for i := sVal; i <= eVal && len(out) < maxItems; i++ {
				var formatted string
				if padZeroes {
					formatted = fmt.Sprintf("%0*d", width, i)
				} else {
					formatted = strconv.Itoa(i)
				}
				sub := prefix + formatted + suffix
				// Recursively expand any subsequent range patterns with depth guard
				subExpanded := expandPattern(sub, maxItems-len(out), depth+1)
				out = append(out, subExpanded...)
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

			for c := sChar; c <= eChar && len(out) < maxItems; c++ {
				sub := prefix + string(c) + suffix
				subExpanded := expandPattern(sub, maxItems-len(out), depth+1)
				out = append(out, subExpanded...)
			}
			return out
		}
	}

	return []string{raw}
}
