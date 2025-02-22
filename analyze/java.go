package analyze

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"bufio"
)

// JavaAnalyzer implements language-specific analysis for Java code
type JavaAnalyzer struct{
	lineMap map[int]string // Maps line numbers to content
}

// NewJavaAnalyzer creates a new instance of JavaAnalyzer
func NewJavaAnalyzer() *JavaAnalyzer {
	return &JavaAnalyzer{
		lineMap: make(map[int]string),
	}
}

// Analyze performs static code analysis on Java code
func (a *JavaAnalyzer) Analyze(filename, content string) ([]string, error) {
	// Load content into line map for reference
	a.buildLineMap(content)
	
	// Start with common checks
	recommendations := CommonChecks(filename, content)

	// Add line-specific analysis for each check
	a.findCatchingThrowable(filename, content, &recommendations)
	a.findEmptyBlocks(filename, content, &recommendations)
	a.findNullChecks(filename, content, &recommendations)
	a.findPublicFields(filename, content, &recommendations)
	a.findExceptionHandling(filename, content, &recommendations)
	a.findHardcodedStrings(filename, content, &recommendations)
	a.checkImports(filename, content, &recommendations)
	a.checkSerialVersionUID(filename, content, &recommendations)
	a.checkLongMethods(filename, content, &recommendations)
	a.checkComplexConditions(filename, content, &recommendations)
	a.checkResourceHandling(filename, content, &recommendations)
	
	return recommendations, nil
}

// buildLineMap creates a mapping of line numbers to line content
func (a *JavaAnalyzer) buildLineMap(content string) {
	scanner := bufio.NewScanner(strings.NewReader(content))
	lineNum := 1
	for scanner.Scan() {
		a.lineMap[lineNum] = scanner.Text()
		lineNum++
	}
}

// getLineNumber finds the line number for a position in the content
func (a *JavaAnalyzer) getLineNumber(content string, position int) int {
	// Count newlines up to the position
	return strings.Count(content[:position], "\n") + 1
}

// findCatchingThrowable checks for catching Throwable
func (a *JavaAnalyzer) findCatchingThrowable(filename, content string, recommendations *[]string) {
	catchThrowablePattern := regexp.MustCompile(`catch\s*\(\s*Throwable\s+(\w+)\s*\)`)
	matches := catchThrowablePattern.FindAllStringSubmatchIndex(content, -1)
	
	for _, match := range matches {
		startPos := match[0]
		lineNum := a.getLineNumber(content, startPos)
		varName := content[match[2]:match[3]]
		
		*recommendations = append(*recommendations, 
			fmt.Sprintf("%s:%d: Catching Throwable '%s' is too broad. Catch more specific exceptions", 
				filename, lineNum, varName))
	}
}

// findEmptyBlocks checks for empty code blocks
func (a *JavaAnalyzer) findEmptyBlocks(filename, content string, recommendations *[]string) {
	// More sophisticated pattern to avoid matching annotations braces
	emptyBlockPattern := regexp.MustCompile(`(?m)(if|for|while|try|catch|else|synchronized).*?\{\s*\}`)
	matches := emptyBlockPattern.FindAllStringIndex(content, -1)
	
	for _, match := range matches {
		startPos := match[0]
		lineNum := a.getLineNumber(content, startPos)
		blockType := regexp.MustCompile(`(if|for|while|try|catch|else|synchronized)`).
			FindString(content[match[0]:match[1]])
		
		*recommendations = append(*recommendations, 
			fmt.Sprintf("%s:%d: Empty %s block. Add comments explaining why or implement properly", 
				filename, lineNum, blockType))
	}
}

// findNullChecks suggests Objects.isNull/nonNull over null checks
func (a *JavaAnalyzer) findNullChecks(filename, content string, recommendations *[]string) {
	nullCheckPattern := regexp.MustCompile(`if\s*\(\s*(\w+)\s*==\s*null\s*\)|\(\s*(\w+)\s*!=\s*null\s*\)`)
	matches := nullCheckPattern.FindAllStringSubmatchIndex(content, -1)
	
	if len(matches) > 5 {
		// Report the first occurrence with line number
		startPos := matches[0][0]
		lineNum := a.getLineNumber(content, startPos)
		
		var varName string
		if matches[0][2] != -1 {
			varName = content[matches[0][2]:matches[0][3]]
		} else if matches[0][4] != -1 {
			varName = content[matches[0][4]:matches[0][5]]
		}
		
		*recommendations = append(*recommendations, 
			fmt.Sprintf("%s:%d: Found %d null checks (e.g., '%s'). Consider using Objects.isNull() and Objects.nonNull()", 
				filename, lineNum, len(matches), varName))
	}
}

// findPublicFields checks for public fields
func (a *JavaAnalyzer) findPublicFields(filename, content string, recommendations *[]string) {
    publicFieldPattern := regexp.MustCompile(`(?m)^\s*public\s+([a-zA-Z0-9_<>]+)\s+([a-zA-Z0-9_]+)\s*[=;]`)
    nonFieldPattern := regexp.MustCompile(`(?m)^\s*public\s+(class|interface|enum|record|static\s+final)`)

    matches := publicFieldPattern.FindAllStringSubmatchIndex(content, -1)

    filteredMatches := make([][]int, 0)

    for _, match := range matches {
        lineStart := match[0]
        lineEnd := strings.Index(content[lineStart:], "\n")
        if lineEnd == -1 {
            lineEnd = len(content)
        } else {
            lineEnd += lineStart
        }

        if !nonFieldPattern.MatchString(content[lineStart:lineEnd]) {
            filteredMatches = append(filteredMatches, match)
        }
    }

    for _, match := range filteredMatches {
        startPos := match[0]
        lineNum := a.getLineNumber(content, startPos)
        fieldType := content[match[2]:match[3]]
        fieldName := content[match[4]:match[5]]

        *recommendations = append(*recommendations,
            fmt.Sprintf("%s:%d: Public field '%s %s'. Consider using private fields with getter/setter methods",
                filename, lineNum, fieldType, fieldName))
    }
}

// findExceptionHandling checks for proper exception handling
func (a *JavaAnalyzer) findExceptionHandling(filename, content string, recommendations *[]string) {
	tryPattern := regexp.MustCompile(`try\s*\{`)
	tryMatches := tryPattern.FindAllStringIndex(content, -1)
	
	// Find try blocks without catch or finally
	for _, match := range tryMatches {
		startPos := match[0]
		tryPos := startPos
		lineNum := a.getLineNumber(content, startPos)
		
		// Check if there's a catch or finally block after this try
		hasCatchOrFinally := false
		if len(content) > startPos+4 {
			blockContent := content[startPos:]
			catchPattern := regexp.MustCompile(`catch\s*\(`)
			finallyPattern := regexp.MustCompile(`finally\s*\{`)
			
			hasCatchOrFinally = catchPattern.MatchString(blockContent) || finallyPattern.MatchString(blockContent)
			
			// More sophisticated: check if catch/finally belongs to this try
			// Skip this advanced check for brevity
		}
		
		if !hasCatchOrFinally {
			*recommendations = append(*recommendations, 
				fmt.Sprintf("%s:%d: Try block without catch or finally. Ensure proper exception handling", 
					filename, lineNum))
		}
		
		// Check empty catch blocks
		emptyCatchPattern := regexp.MustCompile(`catch\s*\([^)]+\)\s*\{\s*\}`)
		if emptyCatchMatches := emptyCatchPattern.FindAllStringIndex(content[tryPos:], -1); len(emptyCatchMatches) > 0 {
			emptyCatchPos := tryPos + emptyCatchMatches[0][0]
			emptyCatchLine := a.getLineNumber(content, emptyCatchPos)
			
			*recommendations = append(*recommendations, 
				fmt.Sprintf("%s:%d: Empty catch block suppresses exceptions. At minimum, add a comment or log", 
					filename, emptyCatchLine))
		}
	}
	
	// Check for generic exception catching
	genericExceptionPattern := regexp.MustCompile(`catch\s*\(\s*Exception\s+(\w+)\s*\)`)
	genericMatches := genericExceptionPattern.FindAllStringSubmatchIndex(content, -1)
	
	for _, match := range genericMatches {
		startPos := match[0]
		lineNum := a.getLineNumber(content, startPos)
		varName := content[match[2]:match[3]]
		
		*recommendations = append(*recommendations, 
			fmt.Sprintf("%s:%d: Catching generic Exception '%s'. Catch more specific exceptions", 
				filename, lineNum, varName))
	}
}

// findHardcodedStrings checks for hardcoded strings
func (a *JavaAnalyzer) findHardcodedStrings(filename, content string, recommendations *[]string) {
	stringLiteralPattern := regexp.MustCompile(`"([^"]{15,})"`)
	matches := stringLiteralPattern.FindAllStringSubmatchIndex(content, -1)
	
	if len(matches) > 3 {
		// Report each long string individually
		for i, match := range matches {
			if i >= 3 { // Limit to first 3 instances to avoid noise
				break
			}
			
			startPos := match[0]
			lineNum := a.getLineNumber(content, startPos)
			stringValue := content[match[2]:match[3]]
			truncated := stringValue
			if len(truncated) > 20 {
				truncated = truncated[:17] + "..."
			}
			
			*recommendations = append(*recommendations, 
				fmt.Sprintf("%s:%d: Long string literal \"%s\". Consider using string constants or resource bundles", 
					filename, lineNum, truncated))
		}
		
		if len(matches) > 3 {
			*recommendations = append(*recommendations, 
				fmt.Sprintf("%s: Found %d more long string literals. Consider using string constants or resource bundles", 
					filename, len(matches)-3))
		}
	}
}

// checkImports checks for too many imports
func (a *JavaAnalyzer) checkImports(filename, content string, recommendations *[]string) {
	importPattern := regexp.MustCompile(`(?m)^import\s+([a-zA-Z0-9_.]+);`)
	matches := importPattern.FindAllStringSubmatchIndex(content, -1)
	
	if len(matches) > 30 {
		// Get first few imports for context
		var importExamples []string
		for i, match := range matches {
			if i >= 3 {
				break
			}
			importExamples = append(importExamples, content[match[2]:match[3]])
		}
		
		firstImportLine := a.getLineNumber(content, matches[0][0])
		
		*recommendations = append(*recommendations, 
			fmt.Sprintf("%s:%d: Found %d imports (e.g., %s). Consider refactoring to reduce dependencies", 
				filename, firstImportLine, len(matches), strings.Join(importExamples, ", ")))
	}
	
	// Check for wildcard imports
	wildcardImportPattern := regexp.MustCompile(`import\s+[a-zA-Z0-9_.]+\.\*;`)
	wildcardMatches := wildcardImportPattern.FindAllStringIndex(content, -1)
	
	if len(wildcardMatches) > 0 {
		startPos := wildcardMatches[0][0]
		lineNum := a.getLineNumber(content, startPos)
		importStmt := strings.TrimSpace(content[wildcardMatches[0][0]:wildcardMatches[0][1]])
		
		*recommendations = append(*recommendations, 
			fmt.Sprintf("%s:%d: Wildcard import '%s'. Import specific classes instead", 
				filename, lineNum, importStmt))
	}
}

// checkSerialVersionUID checks for serialVersionUID
func (a *JavaAnalyzer) checkSerialVersionUID(filename, content string, recommendations *[]string) {
	if strings.Contains(content, "implements Serializable") || strings.Contains(content, "extends.*Serializable") {
		classPattern := regexp.MustCompile(`class\s+([A-Za-z0-9_]+).*?implements.*?Serializable`)
		classMatches := classPattern.FindAllStringSubmatchIndex(content, -1)
		
		if len(classMatches) > 0 && !strings.Contains(content, "serialVersionUID") {
			startPos := classMatches[0][0]
			lineNum := a.getLineNumber(content, startPos)
			className := content[classMatches[0][2]:classMatches[0][3]]
			
			*recommendations = append(*recommendations, 
				fmt.Sprintf("%s:%d: Class '%s' implements Serializable but doesn't define serialVersionUID", 
					filename, lineNum, className))
		}
	}
}

// checkLongMethods identifies methods that are too long
func (a *JavaAnalyzer) checkLongMethods(filename, content string, recommendations *[]string) {
	// Simple method detection - more accurate parser would be better
	methodPattern := regexp.MustCompile(`(?ms)(public|private|protected)?\s+\w+(\s+\w+)?\([^)]*\)\s*(\{[^}]*\})`)
	methodMatches := methodPattern.FindAllStringSubmatchIndex(content, -1)
	
	for _, match := range methodMatches {
		methodStart := match[0]
		methodEnd := match[1]
		methodBody := content[match[6]:match[7]]
		
		// Count lines in method body
		lineCount := strings.Count(methodBody, "\n")
		if lineCount > 50 {
			lineNum := a.getLineNumber(content, methodStart)
			
			// Extract method name
			methodDecl := content[methodStart:methodEnd]
			namePattern := regexp.MustCompile(`\s+(\w+)\s*\(`)
			nameMatch := namePattern.FindStringSubmatchIndex(methodDecl)
			methodName := "unknown"
			if len(nameMatch) >= 4 {
				methodName = methodDecl[nameMatch[2]:nameMatch[3]]
			}
			
			*recommendations = append(*recommendations, 
				fmt.Sprintf("%s:%d: Method '%s' is too long (%d lines). Consider refactoring", 
					filename, lineNum, methodName, lineCount))
		}
	}
}

// checkComplexConditions identifies overly complex conditions
func (a *JavaAnalyzer) checkComplexConditions(filename, content string, recommendations *[]string) {
	// Find if statements with multiple conditions
	complexConditionPattern := regexp.MustCompile(`if\s*\(\s*[^()]*&&.*\|\|.*[^()]*\)`)
	matches := complexConditionPattern.FindAllStringIndex(content, -1)
	
	for _, match := range matches {
		startPos := match[0]
		lineNum := a.getLineNumber(content, startPos)
		condition := content[match[0]:match[1]]
		
		// Count logical operators to determine complexity
		andCount := strings.Count(condition, "&&")
		orCount := strings.Count(condition, "||")
		totalOps := andCount + orCount
		
		if totalOps >= 3 {
			*recommendations = append(*recommendations, 
				fmt.Sprintf("%s:%d: Complex condition with %d logical operators. Consider extracting into a separate method", 
					filename, lineNum, totalOps))
		}
	}
}

// checkResourceHandling checks for proper resource handling
func (a *JavaAnalyzer) checkResourceHandling(filename, content string, recommendations *[]string) {
	// Check for resource usage without try-with-resources
	resourcePattern := regexp.MustCompile(`new\s+(FileInputStream|FileOutputStream|BufferedReader|BufferedWriter|Connection|Statement|ResultSet)\s*\(`)
	resourceMatches := resourcePattern.FindAllStringSubmatchIndex(content, -1)
	
	// Look for try-with-resources usage
	tryWithResourcesPattern := regexp.MustCompile(`try\s*\(\s*\w+`)
	hasTryWithResources := tryWithResourcesPattern.MatchString(content)
	
	if len(resourceMatches) > 0 && !hasTryWithResources {
		startPos := resourceMatches[0][0]
		lineNum := a.getLineNumber(content, startPos)
		resourceType := content[resourceMatches[0][2]:resourceMatches[0][3]]
		
		*recommendations = append(*recommendations, 
			fmt.Sprintf("%s:%d: Using '%s' without try-with-resources. Use 'try (Resource res = new Resource())' for automatic resource management", 
				filename, lineNum, resourceType))
	}
	
	// Check for manual resource closing without finally block
	closeMethodPattern := regexp.MustCompile(`\.close\(\)`)
	closeMatches := closeMethodPattern.FindAllStringIndex(content, -1)
	
	if len(closeMatches) > 0 && !strings.Contains(content, "finally") {
		startPos := closeMatches[0][0]
		lineNum := a.getLineNumber(content, startPos)
		
		prevNewline := strings.LastIndex(content[:startPos], "\n")
		if prevNewline == -1 {
			prevNewline = 0
		}
		
		lineContent := content[prevNewline:startPos+8]
		// Extract the object being closed
		closedObj := regexp.MustCompile(`(\w+)\.close\(\)`).FindStringSubmatch(lineContent)
		objName := "resource"
		if len(closedObj) > 1 {
			objName = closedObj[1]
		}
		
		*recommendations = append(*recommendations, 
			fmt.Sprintf("%s:%d: Manual closing of %s without finally block. Use try-with-resources or ensure close() in finally", 
				filename, lineNum, objName))
	}
}

// AnalyzeJavaCode is a convenience function that creates and uses a JavaAnalyzer
func AnalyzeJavaCode(filename, content string) ([]string, error) {
	// Handle content input by creating a temporary file if needed
	if content != "" {
		tempFile, err := os.CreateTemp("", "*.java")
		if err != nil {
			return nil, fmt.Errorf("failed to create temp file: %w", err)
		}
		defer os.Remove(tempFile.Name())
		if _, err := tempFile.Write([]byte(content)); err != nil {
			return nil, fmt.Errorf("failed to write to temp file: %w", err)
		}
		filepath := tempFile.Name()
		tempFile.Close()
		
		// Update filename if it wasn't provided
		if filename == "" {
			filename = filepath
		}
	}
	
	analyzer := NewJavaAnalyzer()
	return analyzer.Analyze(filename, content)
}