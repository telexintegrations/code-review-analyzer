package analyze

import (
	"fmt"
	"regexp"
	"strings"
)

// Common analysis interface that all language analyzers must implement
type CodeAnalyzer interface {
	Analyze(filename, content string) ([]string, error)
}

// Common patterns shared across multiple languages
var (
	TodoPattern             = regexp.MustCompile(`(?i)TODO:|FIXME:|XXX:|BUG:|HACK:`)
	LongLinePattern         = regexp.MustCompile(`.{100,}`) // Adjust as needed
	TrailingWhitespacePattern = regexp.MustCompile(`[ \t]+$`)
	DebugPrintPattern       = regexp.MustCompile(`(?i)(fmt\.Println|console\.log|print|debug|log\(.*\)|\.dump|\.inspect)`) // Add more as needed
	CommentedOutCodePattern = regexp.MustCompile(`(?m)^\s*//.*`) // Matches commented-out lines
	ComplexComparison       = regexp.MustCompile(`(==|!=|>|<|>=|<=){2,}`) // Detects multiple chained comparisons
	MagicNumberPattern      = regexp.MustCompile(`\b\d+\b`) // Detects raw numbers (customize regex)
)

// Common checks that apply to most languages
func CommonChecks(filename, content string) []string {
	var recommendations []string
	lines := strings.Split(content, "\n")

	// TODOs/FIXMEs
	matches := TodoPattern.FindAllStringIndex(content, -1)
	for _, match := range matches {
		lineNum := getLineNumber(lines, match[0])
		recommendations = append(recommendations, fmt.Sprintf("%s:%d: Review TODO/FIXME", filename, lineNum))
	}

	// Long lines
	for i, line := range lines {
		if LongLinePattern.MatchString(line) {
			recommendations = append(recommendations, fmt.Sprintf("%s:%d: Line too long (%d chars)", filename, i+1, len(line)))
		}
	}

	// Trailing whitespace
	for i, line := range lines {
		if TrailingWhitespacePattern.MatchString(line) {
			recommendations = append(recommendations, fmt.Sprintf("%s:%d: Trailing whitespace", filename, i+1))
		}
	}

	// Debug print statements
	matches = DebugPrintPattern.FindAllStringIndex(content, -1)
	for _, match := range matches {
		lineNum := getLineNumber(lines, match[0])
		recommendations = append(recommendations, fmt.Sprintf("%s:%d: Remove debug print statement", filename, lineNum))
	}

	// Commented-out code
	matches = CommentedOutCodePattern.FindAllStringIndex(content, -1)
	for _, match := range matches {
		lineNum := getLineNumber(lines, match[0])
		recommendations = append(recommendations, fmt.Sprintf("%s:%d: Review commented-out code", filename, lineNum))
	}

	// Complex comparisons
	for i, line := range lines {
		if ComplexComparison.MatchString(line) {
			recommendations = append(recommendations, fmt.Sprintf("%s:%d: Simplify complex comparison", filename, i+1))
		}
	}

	// Magic numbers (customize regex and checks as needed)
	matches = MagicNumberPattern.FindAllStringIndex(content, -1)
	for _, match := range matches {
		lineNum := getLineNumber(lines, match[0])
		number := content[match[0]:match[1]]
		recommendations = append(recommendations, fmt.Sprintf("%s:%d: Use named constant instead of magic number '%s'", filename, lineNum, number))
	}

	return recommendations
}

// Helper function to get line number from character index
func getLineNumber(lines []string, index int) int {
	count := 0
	for i, line := range lines {
		count += len(line) + 1 // +1 for newline character
		if count > index {
			return i + 1
		}
	}
	return len(lines) // If index is beyond the end of the file
}

// AnalyzeThoroughnessInLines performs thoroughness analysis on specific lines
func AnalyzeThoroughnessInLines(filename string, lines []string, startLine, endLine int) []string {
	var recommendations []string
	for i := startLine; i <= endLine; i++ {
		line := lines[i]
		if strings.Contains(line, "err !=") {
			recommendations = append(recommendations, fmt.Sprintf("%s:%d: Missing error handling.", filename, i+1))
		}
		// Add more thoroughness-specific checks here
		if strings.Contains(line, "sync.WaitGroup") { // Example: Check for proper WaitGroup usage
			recommendations = append(recommendations, fmt.Sprintf("%s:%d: Review WaitGroup usage.", filename, i+1))
		}
	}
	return recommendations
}

// AnalyzeClarityInLines performs clarity analysis on specific lines
func AnalyzeClarityInLines(filename string, lines []string, startLine, endLine int) []string {
	var recommendations []string
	for i := startLine; i <= endLine; i++ {
		line := lines[i]
		if strings.Contains(line, "==") || strings.Contains(line, "!=") {
			recommendations = append(recommendations, fmt.Sprintf("%s:%d: Simplify complex comparisons.", filename, i+1))
		}
		if len(line) > 80 {
			recommendations = append(recommendations, fmt.Sprintf("%s:%d: Line too long.", filename, i+1))
		}
		// Add more clarity-specific checks here
		if strings.Contains(line, "interface{}") { // Example: Check for use of empty interface
			recommendations = append(recommendations, fmt.Sprintf("%s:%d: Avoid using empty interface.", filename, i+1))
		}
	}
	return recommendations
}

// AnalyzeActionabilityInLines performs actionability analysis on specific lines
func AnalyzeActionabilityInLines(filename string, lines []string, startLine, endLine int) []string {
	var recommendations []string
	for i := startLine; i <= endLine; i++ {
		line := lines[i]
		if strings.Contains(line, "TODO") || strings.Contains(line, "//") {
			recommendations = append(recommendations, fmt.Sprintf("%s:%d: Review TODOs/commented-out code.", filename, i+1))
		}
		// Add more actionability-specific checks here
		if strings.Contains(line, "panic(") { // Example: Check for panics
			recommendations = append(recommendations, fmt.Sprintf("%s:%d: Avoid panics; use error handling.", filename, i+1))
		}
	}
	return recommendations
}