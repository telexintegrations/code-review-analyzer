package analyze

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// PythonAnalyzer implements comprehensive analysis for Python code
type PythonAnalyzer struct {
	filename string
	content  string
	lines    []string
}

// Issue represents a code issue with severity
type Issue struct {
	File     string
	Line     int
	Column   int
	Message  string
	Severity string // "error", "warning", "info"
	Code     string // issue code (e.g., "PYL001")
}

// NewPythonAnalyzer creates a new analyzer instance
func NewPythonAnalyzer(filename, content string) *PythonAnalyzer {
	return &PythonAnalyzer{
		filename: filename,
		content:  content,
		lines:    strings.Split(content, "\n"),
	}
}

// Analyze performs static code analysis on Python code
func (a *PythonAnalyzer) Analyze() ([]string, error) {
	var recommendations []string
	issues := a.detectIssues()

	// Format the issues into recommendations
	for _, issue := range issues {
		location := fmt.Sprintf("%s:%d", issue.File, issue.Line)
		if issue.Column > 0 {
			location += fmt.Sprintf(":%d", issue.Column)
		}
		
		recommendation := fmt.Sprintf("%s [%s] %s: %s", 
			location, 
			issue.Severity, 
			issue.Code,
			issue.Message)
		
		recommendations = append(recommendations, recommendation)
	}

	return recommendations, nil
}

// detectIssues runs all the issue detection rules
func (a *PythonAnalyzer) detectIssues() []Issue {
	var issues []Issue

	// Run all checkers
	issues = append(issues, a.checkSyntaxErrors()...)
	issues = append(issues, a.checkExceptionHandling()...)
	issues = append(issues, a.checkImports()...)
	issues = append(issues, a.checkFunctionDefinitions()...)
	issues = append(issues, a.checkVariableNaming()...)
	issues = append(issues, a.checkCodeStyle()...)
	issues = append(issues, a.checkSecurityIssues()...)
	issues = append(issues, a.checkPerformanceIssues()...)
	issues = append(issues, a.checkDocstrings()...)

	return issues
}

// checkSyntaxErrors tries to identify basic syntax issues
func (a *PythonAnalyzer) checkSyntaxErrors() []Issue {
	var issues []Issue
	
	// Check for unbalanced parentheses, brackets, and braces
	openChars := map[rune]rune{'(': ')', '[': ']', '{': '}'}
	
	for lineNum, line := range a.lines {
		stack := []rune{}
		for colNum, char := range line {
			if opener, isOpener := openChars[char]; isOpener {
				stack = append(stack, opener)
			} else if char == ')' || char == ']' || char == '}' {
				if len(stack) == 0 || stack[len(stack)-1] != char {
					issues = append(issues, Issue{
						File:     a.filename,
						Line:     lineNum + 1,
						Column:   colNum + 1,
						Message:  fmt.Sprintf("Unbalanced delimiter: '%c'", char),
						Severity: "error",
						Code:     "PYL001",
					})
				} else {
					stack = stack[:len(stack)-1]
				}
			}
		}
	}
	
	// Check for indentation issues
	// expectedIndent := 0
	indentStack := []int{0}
	
	for lineNum, line := range a.lines {
		trimmedLine := strings.TrimSpace(line)
		
		// Skip empty lines and comments
		if trimmedLine == "" || strings.HasPrefix(trimmedLine, "#") {
			continue
		}
		
		// Calculate current indentation
		currentIndent := len(line) - len(strings.TrimLeft(line, " \t"))
		
		// Check for consistent indentation (assuming 4 spaces per level)
		if strings.Contains(line, "\t") && strings.Contains(line, "    ") {
			issues = append(issues, Issue{
				File:     a.filename,
				Line:     lineNum + 1,
				Column:   1,
				Message:  "Mixed tab and space indentation",
				Severity: "error",
				Code:     "PYL002",
			})
		}
		
		// Lines that end with colon increase expected indentation
		if strings.HasSuffix(trimmedLine, ":") {
			indentStack = append(indentStack, currentIndent + 4)
		} else if currentIndent < indentStack[len(indentStack)-1] {
			// Dedent - pop indentation levels that are no longer needed
			for len(indentStack) > 0 && currentIndent < indentStack[len(indentStack)-1] {
				indentStack = indentStack[:len(indentStack)-1]
			}
		}
		
		// If current indent doesn't match any expected indent level
		if currentIndent > 0 && currentIndent != indentStack[len(indentStack)-1] {
			issues = append(issues, Issue{
				File:     a.filename,
				Line:     lineNum + 1,
				Column:   1,
				Message:  fmt.Sprintf("Indentation error: expected %d spaces, got %d", indentStack[len(indentStack)-1], currentIndent),
				Severity: "error",
				Code:     "PYL003",
			})
		}
	}
	
	return issues
}

// checkExceptionHandling checks for exception handling best practices
func (a *PythonAnalyzer) checkExceptionHandling() []Issue {
	var issues []Issue
	
	// Regular expressions for exception handling patterns
	bareExceptRE := regexp.MustCompile(`except\s*:`)
	exceptExceptionRE := regexp.MustCompile(`except\s+Exception\s*:`)
	
	// Check for bare except
	for lineNum, line := range a.lines {
		if bareExceptRE.MatchString(line) {
			issues = append(issues, Issue{
				File:     a.filename,
				Line:     lineNum + 1,
				Column:   strings.Index(line, "except") + 1,
				Message:  "Bare 'except:' clause used. Always catch specific exceptions",
				Severity: "warning",
				Code:     "PYL101",
			})
		}
		
		if exceptExceptionRE.MatchString(line) {
			issues = append(issues, Issue{
				File:     a.filename,
				Line:     lineNum + 1,
				Column:   strings.Index(line, "except") + 1,
				Message:  "'except Exception:' used. Catch specific exceptions instead",
				Severity: "warning",
				Code:     "PYL102",
			})
		}
		
		// Check for pass in except block
		if strings.Contains(line, "except") && lineNum+1 < len(a.lines) {
			nextLine := strings.TrimSpace(a.lines[lineNum+1])
			if nextLine == "pass" {
				issues = append(issues, Issue{
					File:     a.filename,
					Line:     lineNum + 2,
					Column:   1,
					Message:  "Empty except block with 'pass'. Either handle the exception or add a comment explaining why it is ignored",
					Severity: "warning",
					Code:     "PYL103",
				})
			}
		}
	}
	
	return issues
}

// checkImports reviews import statements for best practices
func (a *PythonAnalyzer) checkImports() []Issue {
	var issues []Issue
	
	importStarRE := regexp.MustCompile(`from\s+(\w+)\s+import\s+\*`)

	// Import order checking
    // importGroups := []string{"standard", "third-party", "local"}
    importLines := make(map[string][]int) // Store line numbers for each group
	
	for lineNum, line := range a.lines {
		trimmedLine := strings.TrimSpace(line)
		// Check for wildcard imports
		if matches := importStarRE.FindStringSubmatch(line); len(matches) > 0 {
			issues = append(issues, Issue{
				File:     a.filename,
				Line:     lineNum + 1,
				Column:   strings.Index(line, "import *") + 1,
				Message:  fmt.Sprintf("Wildcard import from '%s'. Explicitly import only what you need", matches[1]),
				Severity: "warning",
				Code:     "PYL201",
			})
		}
		
		// Check for import order (standard, third-party, local)
		// This is a simplified check, would need multi-line tracking for completeness
		if strings.HasPrefix(trimmedLine, "import ") || strings.HasPrefix(trimmedLine, "from ") {
            group := determineImportGroup(trimmedLine)
            importLines[group] = append(importLines[group], lineNum+1)
        }
	}

	// Check import order
    expectedOrder := []string{"standard", "third-party", "local"}
    seenGroups := make(map[string]bool)

    for _, group := range expectedOrder {
        if lines, ok := importLines[group]; ok {
            if seenGroups[group] {
                // Duplicate group - not necessarily an error, but could indicate messy imports
                // You might want to add a warning here if you are strict.
				// Duplicate group - report a warning
                issues = append(issues, Issue{
                    File:     a.filename,
                    Line:     lines[0], // Report on the first occurrence of the duplicate
                    Column:   1,
                    Message:  fmt.Sprintf("Duplicate import group '%s' found.  Imports should be grouped together.", group),
                    Severity: "info", // Or "warning" if you want to be stricter
                    Code:     "PYL204", // New code for duplicate group
                })
            }
            seenGroups[group] = true

            if len(lines) > 1 { // Check within-group ordering (alphabetical)
                for i := 0; i < len(lines)-1; i++ {
                    line1 := a.lines[lines[i]-1]
                    line2 := a.lines[lines[i+1]-1]

                    import1 := extractImportName(line1)
                    import2 := extractImportName(line2)

                    if import1 > import2 { // Not in alphabetical order
                        issues = append(issues, Issue{
                            File:     a.filename,
                            Line:     lines[i+1],
                            Column:   1,
                            Message:  fmt.Sprintf("Imports in group '%s' are not in alphabetical order", group),
                            Severity: "info",
                            Code:     "PYL202",
                        })
                    }
                }
            }
        }
    }

    // Check for correct group order
    groupIndex := 0
    for _, group := range expectedOrder {
        if _, ok := importLines[group]; ok {
            if groupIndex > 0 { // Check against the previous group
                prevGroup := expectedOrder[groupIndex-1]
                if _, ok := importLines[prevGroup]; ok {
                    prevLines := importLines[prevGroup]
                    currentLines := importLines[group]
                    if prevLines[len(prevLines)-1] > currentLines[0] {
                        issues = append(issues, Issue{
                            File:     a.filename,
                            Line:     currentLines[0],
                            Column:   1,
                            Message:  "Imports are not grouped in the correct order (standard, third-party, local)",
                            Severity: "info",
                            Code:     "PYL203",
                        })

                    }

                }
            }
            groupIndex++
        }
    }
	
	return issues
}

func determineImportGroup(line string) string {
    // Very basic example -  customize as needed!
    if strings.Contains(line, "my_local_module") { // Example local module
        return "local"
    } else if strings.Contains(line, "requests") || strings.Contains(line, "numpy") { // Example third-party
        return "third-party"
    }
    return "standard" // Default to standard library
}

func extractImportName(line string) string {
    parts := strings.Fields(line)
    if len(parts) > 1 {
        if parts[0] == "import" {
            return parts[1]
        } else if parts[0] == "from" {
            return parts[1] // Or handle "from x import y" differently if needed
        }
    }
    return line // Return the whole line if parsing fails
}

// checkFunctionDefinitions analyzes function definitions
func (a *PythonAnalyzer) checkFunctionDefinitions() []Issue {
	var issues []Issue
	
	// Check for mutable default arguments
	mutableDefaultRE := regexp.MustCompile(`def\s+\w+\([^)]*?(\w+)\s*=\s*(\[\]|\{\}|\(\))`)
	
	inFunction := false
	functionName := ""
	functionStart := 0
	functionLineCount := 0
	functionIndent := 0
	
	for lineNum, line := range a.lines {
		trimmedLine := strings.TrimSpace(line)
		
		// Skip empty lines and comments
		if trimmedLine == "" || strings.HasPrefix(trimmedLine, "#") {
			continue
		}
		
		// Check for mutable default arguments
		if matches := mutableDefaultRE.FindStringSubmatch(line); len(matches) > 0 {
			issues = append(issues, Issue{
				File:     a.filename,
				Line:     lineNum + 1,
				Column:   strings.Index(line, matches[2]) + 1,
				Message:  fmt.Sprintf("Mutable default argument '%s=%s' can cause unexpected behavior", matches[1], matches[2]),
				Severity: "warning",
				Code:     "PYL301",
			})
		}
		
		// Function complexity tracking
		if strings.HasPrefix(trimmedLine, "def ") {
			// Extract function name
			funcNameRE := regexp.MustCompile(`def\s+(\w+)\s*\(`)
			nameMatches := funcNameRE.FindStringSubmatch(trimmedLine)
			
			if len(nameMatches) > 0 {
				// End previous function if we're in one
				if inFunction {
					if functionLineCount > 50 {
						issues = append(issues, Issue{
							File:     a.filename,
							Line:     functionStart + 1,
							Column:   1,
							Message:  fmt.Sprintf("Function '%s' is too long (%d lines). Consider refactoring", functionName, functionLineCount),
							Severity: "warning", 
							Code:     "PYL302",
						})
					}
				}
				
				// Start new function
				inFunction = true
				functionName = nameMatches[1]
				functionStart = lineNum
				functionLineCount = 1
				functionIndent = len(line) - len(strings.TrimLeft(line, " \t"))
			}
		} else if inFunction {
			// Check if we're still in the function by indentation
			lineIndent := len(line) - len(strings.TrimLeft(line, " \t"))
			if lineIndent <= functionIndent && trimmedLine != "" {
				// Function ended
				if functionLineCount > 50 {
					issues = append(issues, Issue{
						File:     a.filename,
						Line:     functionStart + 1,
						Column:   1,
						Message:  fmt.Sprintf("Function '%s' is too long (%d lines). Consider refactoring", functionName, functionLineCount),
						Severity: "warning",
						Code:     "PYL302",
					})
				}
				inFunction = false
			} else {
				functionLineCount++
			}
		}
	}
	
	// Check the last function if we're still tracking one
	if inFunction && functionLineCount > 50 {
		issues = append(issues, Issue{
			File:     a.filename,
			Line:     functionStart + 1,
			Column:   1,
			Message:  fmt.Sprintf("Function '%s' is too long (%d lines). Consider refactoring", functionName, functionLineCount),
			Severity: "warning",
			Code:     "PYL302",
		})
	}
	
	return issues
}

// checkVariableNaming checks variable naming conventions
func (a *PythonAnalyzer) checkVariableNaming() []Issue {
	var issues []Issue
	
	// Regular expressions for variable declarations
	variableAssignRE := regexp.MustCompile(`^\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*=`)
	constantRE := regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)
	camelCaseRE := regexp.MustCompile(`^[a-z][a-zA-Z0-9]*$`)
	snakeCaseRE := regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
	
	for lineNum, line := range a.lines {
		if matches := variableAssignRE.FindStringSubmatch(line); len(matches) > 0 {
			varName := matches[1]
			
			// Skip special names like __init__, etc.
			if strings.HasPrefix(varName, "__") && strings.HasSuffix(varName, "__") {
				continue
			}
			
			// Check if name is a constant but not in UPPER_CASE
			if strings.ToUpper(varName) == varName && !constantRE.MatchString(varName) {
				issues = append(issues, Issue{
					File:     a.filename,
					Line:     lineNum + 1,
					Column:   strings.Index(line, varName) + 1,
					Message:  fmt.Sprintf("Variable '%s' appears to be a constant but doesn't follow UPPER_CASE naming", varName),
					Severity: "info",
					Code:     "PYL401",
				})
			}
			
			// Check for consistent naming style - prefer snake_case in Python
			if !constantRE.MatchString(varName) && !snakeCaseRE.MatchString(varName) && camelCaseRE.MatchString(varName) {
				issues = append(issues, Issue{
					File:     a.filename,
					Line:     lineNum + 1,
					Column:   strings.Index(line, varName) + 1,
					Message:  fmt.Sprintf("Variable '%s' uses camelCase but Python convention is snake_case", varName),
					Severity: "info", 
					Code:     "PYL402",
				})
			}
		}
	}
	
	return issues
}

// checkCodeStyle reviews general code style issues
func (a *PythonAnalyzer) checkCodeStyle() []Issue {
	var issues []Issue
	
	// Check line length
	for lineNum, line := range a.lines {
		if len(line) > 100 {
			issues = append(issues, Issue{
				File:     a.filename,
				Line:     lineNum + 1,
				Column:   100,
				Message:  fmt.Sprintf("Line too long (%d characters, max suggested 100)", len(line)),
				Severity: "info",
				Code:     "PYL501",
			})
		}
	}
	
	// Check for consistent quotes
	singleQuotes := 0
	doubleQuotes := 0
	
	// More sophisticated quote counting (ignoring quotes inside other quotes)
	inSingleQuote := false
	inDoubleQuote := false
	
	for _, line := range a.lines {
		for _, char := range line {
			if char == '\'' && !inDoubleQuote {
				inSingleQuote = !inSingleQuote
				singleQuotes++
			} else if char == '"' && !inSingleQuote {
				inDoubleQuote = !inDoubleQuote
				doubleQuotes++
			}
		}
		
		// Reset quote state at end of line
		inSingleQuote = false
		inDoubleQuote = false
	}
	
	// Determine if quote usage is inconsistent
	if singleQuotes > 0 && doubleQuotes > 0 {
		if singleQuotes > doubleQuotes*3 || doubleQuotes > singleQuotes*3 {
			issues = append(issues, Issue{
				File:     a.filename,
				Line:     1,
				Column:   1,
				Message:  "Inconsistent quote style. Consider using consistent string quotes",
				Severity: "info",
				Code:     "PYL502",
			})
		}
	}
	
	return issues
}

// checkSecurityIssues looks for common security problems
func (a *PythonAnalyzer) checkSecurityIssues() []Issue {
	var issues []Issue
	
	// Check for potential SQL injection
	sqlInjectionRE := regexp.MustCompile(`(?i)(execute|executemany|cursor\.execute)\s*\(\s*[f"'].*?\%.*?['"]\s*.*?\)|execute\s*\(\s*["'].*?\s*\+`)
	
	// Check for potential shell injection
	shellInjectionRE := regexp.MustCompile(`(?i)(os\.system|subprocess\.call|subprocess\.Popen|exec|eval)\s*\(\s*[f"'].*?\{.*?\}.*?['"]|.*?\+`)
	
	for lineNum, line := range a.lines {
		if sqlInjectionRE.MatchString(line) {
			issues = append(issues, Issue{
				File:     a.filename,
				Line:     lineNum + 1,
				Column:   1,
				Message:  "Potential SQL injection vulnerability. Use parameterized queries instead",
				Severity: "error",
				Code:     "PYL601",
			})
		}
		
		if shellInjectionRE.MatchString(line) {
			issues = append(issues, Issue{
				File:     a.filename,
				Line:     lineNum + 1,
				Column:   1,
				Message:  "Potential shell injection vulnerability. Sanitize user input before using in shell commands",
				Severity: "error",
				Code:     "PYL602",
			})
		}
		
		// Check for hard-coded credentials
		if strings.Contains(line, "password") && (strings.Contains(line, "=") || strings.Contains(line, ":")) {
			passwordRE := regexp.MustCompile(`(?i)password\s*[=:]\s*['"][^'"]+['"]`)
			if passwordRE.MatchString(line) {
				issues = append(issues, Issue{
					File:     a.filename,
					Line:     lineNum + 1,
					Column:   strings.Index(strings.ToLower(line), "password"),
					Message:  "Hard-coded password detected. Use environment variables or a secure configuration system",
					Severity: "error",
					Code:     "PYL603",
				})
			}
		}
	}
	
	return issues
}

// checkPerformanceIssues checks for common performance problems
func (a *PythonAnalyzer) checkPerformanceIssues() []Issue {
	var issues []Issue
	
	// Check for inefficient list operations in loops
	for lineNum, line := range a.lines {
		trimmedLine := strings.TrimSpace(line)
		
		// Check for list concatenation in loops
		if strings.Contains(trimmedLine, "for ") {
			// Look ahead for list += operations
			if lineNum+1 < len(a.lines) && strings.Contains(a.lines[lineNum+1], " += [") {
				issues = append(issues, Issue{
					File:     a.filename,
					Line:     lineNum + 2,
					Column:   1,
					Message:  "List concatenation in loop is inefficient. Consider using list.append() or a list comprehension",
					Severity: "warning",
					Code:     "PYL701",
				})
			}
		}
		
		// Check for inefficient string concatenation
		if strings.Contains(trimmedLine, "for ") && lineNum+2 < len(a.lines) {
			nextLines := a.lines[lineNum+1] + a.lines[lineNum+2]
			if strings.Contains(nextLines, " += \"") || strings.Contains(nextLines, " += '") {
				issues = append(issues, Issue{
					File:     a.filename,
					Line:     lineNum + 1,
					Column:   1,
					Message:  "String concatenation in loop is inefficient. Use ''.join() or string formatting instead",
					Severity: "warning",
					Code:     "PYL702",
				})
			}
		}
	}
	
	return issues
}

// checkDocstrings verifies presence and format of docstrings
func (a *PythonAnalyzer) checkDocstrings() []Issue {
	var issues []Issue
	
	// Track function/class definitions and check for docstrings
	funcClassRE := regexp.MustCompile(`^\s*(def|class)\s+(\w+)`)
	
	for lineNum, line := range a.lines {
		matches := funcClassRE.FindStringSubmatch(line)
		if len(matches) > 0 {
			defType := matches[1]
			name := matches[2]
			
			// Skip if this is a private method/function
			if strings.HasPrefix(name, "_") && !strings.HasPrefix(name, "__") && !strings.HasSuffix(name, "__") {
				continue
			}
			
			// Look for docstring in the next 2 lines
			hasDocstring := false
			for i := 1; i <= 2 && lineNum+i < len(a.lines); i++ {
				nextLine := strings.TrimSpace(a.lines[lineNum+i])
				if strings.HasPrefix(nextLine, "\"\"\"") || strings.HasPrefix(nextLine, "'''") {
					hasDocstring = true
					break
				}
				// If we hit non-comment code, stop looking
				if nextLine != "" && !strings.HasPrefix(nextLine, "#") && nextLine != "pass" {
					break
				}
			}
			
			if !hasDocstring {
				issues = append(issues, Issue{
					File:     a.filename,
					Line:     lineNum + 1,
					Column:   strings.Index(line, defType),
					Message:  fmt.Sprintf("Missing docstring for %s '%s'", defType, name),
					Severity: "info",
					Code:     "PYL801",
				})
			}
		}
	}
	
	return issues
}

// AnalyzePythonCode is a convenience function that creates and uses a PythonAnalyzer
func AnalyzePythonCode(filename, content string) ([]string, error) {
	// If empty content but filename is provided, try to read the file
	if content == "" && filename != "" {
		fileContent, err := readFileContent(filename)
		if err != nil {
			return []string{fmt.Sprintf("Failed to read file %s: %v", filename, err)}, nil
		}
		content = fileContent
	}
	
	// Use basename of the file path for reporting
	reportFilename := filepath.Base(filename)
	if reportFilename == "" {
		reportFilename = "unnamed.py"
	}
	
	analyzer := NewPythonAnalyzer(reportFilename, content)
	return analyzer.Analyze()
}

// Helper function to read file content
func readFileContent(filepath string) (string, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	var content strings.Builder
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		content.WriteString(scanner.Text() + "\n")
	}

	if err := scanner.Err(); err != nil {
		return "", err
	}

	return content.String(), nil
}