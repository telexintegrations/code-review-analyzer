package analyze

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

// PHPSecurityIssue represents a security vulnerability or code quality issue
type PHPSecurityIssue struct {
	Type        string
	Description string
	Severity    string // "Critical", "High", "Medium", "Low", "Info"
	Line        int
	Column      int
	Snippet     string
}

// PHPStanOutput represents the output format from PHPStan
type PHPStanOutput struct {
	Files map[string]struct {
		Errors []struct {
			Message string `json:"message"`
			Line    int    `json:"line"`
			Column  int    `json:"column"`
		} `json:"messages"`
	} `json:"files"`
}

// PHPAnalyzer implements comprehensive PHP code analysis
type PHPAnalyzer struct {
	UsePHPStan      bool
	PHPStanPath     string
	IncludeSnippets bool
}

// NewPHPAnalyzer creates a new analyzer with default settings
func NewPHPAnalyzer() *PHPAnalyzer {
	return &PHPAnalyzer{
		UsePHPStan:      true,
		PHPStanPath:     "phpstan",
		IncludeSnippets: true,
	}
}

// Analyze performs static code analysis on PHP code
func (a *PHPAnalyzer) Analyze(filepath string, content string) ([]string, error) {
	allIssues := []PHPSecurityIssue{}
	
	// Run static analysis
	staticIssues, err := a.performStaticAnalysis(filepath, content)
	if err != nil {
		return nil, fmt.Errorf("static analysis failed: %w", err)
	}
	allIssues = append(allIssues, staticIssues...)
	
	// Run PHPStan if enabled
	if a.UsePHPStan {
		phpstanIssues, err := a.runPHPStan(filepath, content)
		if err == nil {
			allIssues = append(allIssues, phpstanIssues...)
		}
	}
	
	// Format issues as recommendations
	recommendations := formatIssuesAsRecommendations(allIssues)
	
	return recommendations, nil
}

// performStaticAnalysis conducts regex-based static analysis on the PHP code
func (a *PHPAnalyzer) performStaticAnalysis(filename string, content string) ([]PHPSecurityIssue, error) {
	var issues []PHPSecurityIssue
	
	// Security vulnerabilities patterns
	securityChecks := []struct {
		Type        string
		Pattern     *regexp.Regexp
		Description string
		Severity    string
	}{
		{
			Type:        "SQL_INJECTION",
			Pattern:     regexp.MustCompile(`(?i)(mysqli_query|->query|->exec|PDO::query)\s*\(\s*.*\$`),
			Description: "Potential SQL injection vulnerability. Use prepared statements with parameters",
			Severity:    "Critical",
		},
		{
			Type:        "XSS",
			Pattern:     regexp.MustCompile(`(?i)echo\s+\$_(GET|POST|REQUEST|COOKIE)`),
			Description: "Potential XSS vulnerability. Sanitize user input before output",
			Severity:    "Critical",
		},
		{
			Type:        "COMMAND_INJECTION",
			Pattern:     regexp.MustCompile(`(?i)(system|exec|shell_exec|passthru|proc_open)\s*\(\s*.*\$`),
			Description: "Potential command injection vulnerability. Validate and sanitize inputs",
			Severity:    "Critical",
		},
		{
			Type:        "EVAL_USAGE",
			Pattern:     regexp.MustCompile(`\b(eval|assert)\s*\(`),
			Description: "Use of eval() or assert() with dynamic content is dangerous and should be avoided",
			Severity:    "Critical",
		},
		{
			Type:        "FILE_INCLUSION",
			Pattern:     regexp.MustCompile(`(?i)(include|require|include_once|require_once)\s*\(\s*.*\$`),
			Description: "Potential file inclusion vulnerability. Validate file paths",
			Severity:    "High",
		},
		{
			Type:        "CSRF_MISSING",
			Pattern:     regexp.MustCompile(`(?i)<form[^>]*method\s*=\s*["']post["'][^>]*>`),
			Description: "Form without CSRF protection. Implement CSRF tokens",
			Severity:    "High",
		},
		{
			Type:        "PASSWORD_HASH",
			Pattern:     regexp.MustCompile(`(?i)(md5|sha1)\s*\(`),
			Description: "Weak hashing algorithm. Use password_hash() for passwords",
			Severity:    "High",
		},
		{
			Type:        "OPEN_REDIRECT",
			Pattern:     regexp.MustCompile(`(?i)header\s*\(\s*["']Location:\s*\$`),
			Description: "Potential open redirect vulnerability. Validate redirect URLs",
			Severity:    "Medium",
		},
		{
			Type:        "DEPRECATED_FUNCTION",
			Pattern:     regexp.MustCompile(`\b(mysql_|ereg_|split|create_function|mcrypt_|session_unregister|define_syslog_variables)\b`),
			Description: "Deprecated PHP function found. Update to modern alternatives",
			Severity:    "Medium",
		},
		{
			Type:        "ERROR_SUPPRESSION",
			Pattern:     regexp.MustCompile(`@[a-zA-Z0-9_]+\(`),
			Description: "Error suppression operator (@) used. Handle errors properly instead",
			Severity:    "Medium",
		},
		{
			Type:        "HARDCODED_CREDENTIALS",
			Pattern:     regexp.MustCompile(`(?i)["'](password|passwd|pwd|secret|key)["']\s*=>\s*["'][^"']{4,}["']`),
			Description: "Potential hardcoded credentials. Use environment variables or secure configuration",
			Severity:    "High",
		},
		{
			Type:        "FILE_UPLOAD",
			Pattern:     regexp.MustCompile(`(?i)\$_FILES\s*\[`),
			Description: "File upload detected. Ensure proper validation of file types and content",
			Severity:    "Medium",
		},
		{
			Type:        "SESSION_SECURITY",
			Pattern:     regexp.MustCompile(`(?i)session_start\s*\(`),
			Description: "Session management detected. Ensure proper session security",
			Severity:    "Info",
		},
	}
	
	// Code quality patterns
	qualityChecks := []struct {
		Type        string
		Pattern     *regexp.Regexp
		Description string
		Severity    string
	}{
		{
			Type:        "MISSING_NAMESPACE",
			Pattern:     regexp.MustCompile(`^<\?php`),
			Description: "No namespace defined. Modern PHP code should use namespaces",
			Severity:    "Low",
		},
		{
			Type:        "LOWERCASE_CONSTANTS",
			Pattern:     regexp.MustCompile(`const\s+([a-z][a-zA-Z0-9_]*)\s*=`),
			Description: "Constants should use uppercase names (CONST_NAME)",
			Severity:    "Low",
		},
		{
			Type:        "MIXED_HTML_PHP",
			Pattern:     regexp.MustCompile(`\?>.*<\?php`),
			Description: "Mixed PHP and HTML detected. Consider using a template engine",
			Severity:    "Low",
		},
		{
			Type:        "VAR_DUMP_PRINT_R",
			Pattern:     regexp.MustCompile(`\b(var_dump|print_r)\s*\(`),
			Description: "Debugging functions found. Remove before production",
			Severity:    "Medium",
		},
		{
			Type:        "ISSET_EMPTY_COMPARISON",
			Pattern:     regexp.MustCompile(`(?:==\s*null|!=\s*null|===\s*null|!==\s*null)`),
			Description: "Use isset() or empty() for null checks instead of comparison",
			Severity:    "Low",
		},
		{
			Type:        "UNUSED_USE_STATEMENT",
			Pattern:     regexp.MustCompile(`use\s+([^;]+);`),
			Description: "Potentially unused use statement. Verify usage",
			Severity:    "Info",
		},
		{
			Type:        "GLOBAL_USAGE",
			Pattern:     regexp.MustCompile(`global\s+\$`),
			Description: "Use of global variables. Consider dependency injection instead",
			Severity:    "Medium",
		},
		{
			Type:        "EXIT_DIE_USAGE",
			Pattern:     regexp.MustCompile(`\b(exit|die)\s*\(`),
			Description: "Use of exit() or die(). Consider structured exception handling instead",
			Severity:    "Low",
		},
		{
			Type:        "INCONSISTENT_LINE_ENDINGS",
			Pattern:     regexp.MustCompile(`\r\n.*\n`),
			Description: "Inconsistent line endings (mixed CRLF and LF)",
			Severity:    "Info",
		},
	}
	
	// Conduct security checks
	for _, check := range securityChecks {
		lineNumbers := findLineNumbers(content, check.Pattern)
		for _, lineInfo := range lineNumbers {
			issue := PHPSecurityIssue{
				Type:        check.Type,
				Description: check.Description,
				Severity:    check.Severity,
				Line:        lineInfo.LineNum,
				Column:      lineInfo.ColumnNum,
			}
			if a.IncludeSnippets {
				issue.Snippet = extractLineSnippet(content, lineInfo.LineNum)
			}
			issues = append(issues, issue)
		}
	}
	
	// Conduct code quality checks
	for _, check := range qualityChecks {
		lineNumbers := findLineNumbers(content, check.Pattern)
		for _, lineInfo := range lineNumbers {
			issue := PHPSecurityIssue{
				Type:        check.Type,
				Description: check.Description,
				Severity:    check.Severity,
				Line:        lineInfo.LineNum,
				Column:      lineInfo.ColumnNum,
			}
			if a.IncludeSnippets {
				issue.Snippet = extractLineSnippet(content, lineInfo.LineNum)
			}
			issues = append(issues, issue)
		}
	}
	
	// PHP version compatibility checks
	// TODO: Add more comprehensive PHP version compatibility checks
	
	// Check for missing security headers in framework files
	if strings.Contains(filename, "controller") || strings.Contains(filename, "Controller") {
		if !strings.Contains(content, "X-Frame-Options") && !strings.Contains(content, "X-XSS-Protection") {
			issues = append(issues, PHPSecurityIssue{
				Type:        "MISSING_SECURITY_HEADERS",
				Description: "Missing security headers. Consider setting X-Frame-Options, X-XSS-Protection, etc.",
				Severity:    "Medium",
				Line:        1,
			})
		}
	}
	
	return issues, nil
}

// runPHPStan executes PHPStan on the PHP code
func (a *PHPAnalyzer) runPHPStan(filePath string, content string) ([]PHPSecurityIssue, error) {
	var issues []PHPSecurityIssue
	var tmpFile *os.File
	var err error
	
	// If content is provided, write it to a temporary file
	if content != "" {
		tmpFile, err = os.CreateTemp("", "php-analysis-*.php")
		if err != nil {
			return nil, fmt.Errorf("failed to create temp file: %w", err)
		}
		defer os.Remove(tmpFile.Name())
		
		if _, err := tmpFile.Write([]byte(content)); err != nil {
			return nil, fmt.Errorf("failed to write to temp file: %w", err)
		}
		tmpFile.Close()
		filePath = tmpFile.Name()
	}
	
	// Run PHPStan
	cmd := exec.Command(a.PHPStanPath, "analyze", filePath, "--no-progress", "--format=json", "--level=5")
	output, err := cmd.CombinedOutput()
	
	// Handle PHPStan execution errors
	if err != nil {
		// If it's just failing because PHPStan found issues, that's expected
		if !strings.Contains(string(output), "Could not open input file") && 
           !strings.Contains(string(output), "Command 'phpstan' not found") {
			// Continue processing the output to get the actual issues
		} else {
			return issues, fmt.Errorf("PHPStan analysis failed: %s", output)
		}
	}
	
	// Parse PHPStan output
	var phpStanOutput PHPStanOutput
	if err := json.Unmarshal(output, &phpStanOutput); err != nil {
		return issues, fmt.Errorf("failed to parse PHPStan output: %w", err)
	}
	
	// Convert PHPStan issues to our format
	for _, fileIssues := range phpStanOutput.Files {
		for _, phpstanIssue := range fileIssues.Errors {
			severity := "Medium" // Default severity
			
			// Determine severity based on message content
			if strings.Contains(phpstanIssue.Message, "security") || 
               strings.Contains(phpstanIssue.Message, "injection") ||
               strings.Contains(phpstanIssue.Message, "XSS") {
				severity = "Critical"
			} else if strings.Contains(phpstanIssue.Message, "deprecated") {
				severity = "Medium"
			} else if strings.Contains(phpstanIssue.Message, "unused") {
				severity = "Low"
			}
			
			issue := PHPSecurityIssue{
				Type:        "PHPSTAN",
				Description: phpstanIssue.Message,
				Severity:    severity,
				Line:        phpstanIssue.Line,
				Column:      phpstanIssue.Column,
			}
			
			if a.IncludeSnippets && content != "" {
				issue.Snippet = extractLineSnippet(content, phpstanIssue.Line)
			}
			
			issues = append(issues, issue)
		}
	}
	
	return issues, nil
}

// LinePosition represents the position of a match in the source code
type LinePosition struct {
	LineNum   int
	ColumnNum int
}

// findLineNumbers finds line and column numbers for all matches of a regex pattern
func findLineNumbers(content string, pattern *regexp.Regexp) []LinePosition {
	lines := strings.Split(content, "\n")
	var positions []LinePosition
	
	for i, line := range lines {
		matches := pattern.FindAllStringIndex(line, -1)
		for _, match := range matches {
			positions = append(positions, LinePosition{
				LineNum:   i + 1,
				ColumnNum: match[0] + 1,
			})
		}
	}
	
	return positions
}

// extractLineSnippet gets a snippet of code around the specified line
func extractLineSnippet(content string, lineNum int) string {
	lines := strings.Split(content, "\n")
	if lineNum <= 0 || lineNum > len(lines) {
		return ""
	}
	
	// Get context around the line
	start := max(0, lineNum-2)
	end := min(len(lines), lineNum+1)
	
	var snippet strings.Builder
	for i := start; i < end; i++ {
		if i == lineNum-1 {
			snippet.WriteString("--> ")
		} else {
			snippet.WriteString("    ")
		}
		snippet.WriteString(fmt.Sprintf("%d: %s\n", i+1, lines[i]))
	}
	
	return snippet.String()
}

// formatIssuesAsRecommendations converts issues to string recommendations
func formatIssuesAsRecommendations(issues []PHPSecurityIssue) []string {
	var recommendations []string
	
	// Group issues by severity
	issuesBySeverity := make(map[string][]PHPSecurityIssue)
	for _, issue := range issues {
		issuesBySeverity[issue.Severity] = append(issuesBySeverity[issue.Severity], issue)
	}
	
	// Process issues in order of severity
	for _, severity := range []string{"Critical", "High", "Medium", "Low", "Info"} {
		severityIssues := issuesBySeverity[severity]
		if len(severityIssues) == 0 {
			continue
		}
		
		// Add a severity header
		recommendations = append(recommendations, fmt.Sprintf("--- %s Issues (%d) ---", strings.ToUpper(severity), len(severityIssues)))
		
		// Group common issues
		issuesByType := make(map[string][]PHPSecurityIssue)
		for _, issue := range severityIssues {
			issuesByType[issue.Type] = append(issuesByType[issue.Type], issue)
		}
		
		// Format each issue type
		for issueType, typeIssues := range issuesByType {
			if len(typeIssues) > 3 {
				// Summarize multiple similar issues
				locations := make([]string, min(3, len(typeIssues)))
				for i := 0; i < min(3, len(typeIssues)); i++ {
					locations[i] = fmt.Sprintf("line %d", typeIssues[i].Line)
				}
				recommendation := fmt.Sprintf("%s: %s (Found at %s and %d more locations)", 
					issueType, typeIssues[0].Description, strings.Join(locations, ", "), len(typeIssues)-3)
				recommendations = append(recommendations, recommendation)
			} else {
				// Report individual issues
				for _, issue := range typeIssues {
					recommendation := fmt.Sprintf("%s [L%d:C%d]: %s", 
						issueType, issue.Line, issue.Column, issue.Description)
					if issue.Snippet != "" {
						recommendation += fmt.Sprintf("\nCode context:\n%s", issue.Snippet)
					}
					recommendations = append(recommendations, recommendation)
				}
			}
		}
	}
	
	return recommendations
}

// AnalyzePHPCode is a convenience function that creates and uses a PHPAnalyzer
func AnalyzePHPCode(filename string, content string) ([]string, error) {
	analyzer := NewPHPAnalyzer()
	return analyzer.Analyze(filename, content)
}

// max returns the larger of x or y
func max(x, y int) int {
	if x > y {
		return x
	}
	return y
}

// min returns the smaller of x or y
func min(x, y int) int {
	if x < y {
		return x
	}
	return y
}

// ScanDirectory scans all PHP files in a directory recursively
func ScanDirectory(dirPath string) (map[string][]string, error) {
	results := make(map[string][]string)
	analyzer := NewPHPAnalyzer()
	
	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		
		// Skip directories
		if info.IsDir() {
			return nil
		}
		
		// Only process PHP files
		if !strings.HasSuffix(strings.ToLower(path), ".php") {
			return nil
		}
		
		// Read file content
		content, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("failed to read file %s: %w", path, err)
		}
		
		// Analyze the file
		recommendations, err := analyzer.Analyze(path, string(content))
		if err != nil {
			return fmt.Errorf("failed to analyze file %s: %w", path, err)
		}
		
		// Store results
		if len(recommendations) > 0 {
			results[path] = recommendations
		}
		
		return nil
	})
	
	return results, err
}