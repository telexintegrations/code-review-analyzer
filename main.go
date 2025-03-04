package main

import (
	// "bytes"
	// "encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os/exec"
	"path/filepath"
	"sync"

	// "io"
	"code-review-analyzer/analyze"
	"code-review-analyzer/models"
	"log"
	"math"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// RepositoryService handles code retrieval from different repository sources
type RepositoryService struct {
	httpClient *http.Client
}

// Global variable to store history (in production, use database)
var analysisHistories = make(map[string][]models.AnalysisHistory)

// NewRepositoryService creates a new repository service
func NewRepositoryService() *RepositoryService {
	return &RepositoryService{
		httpClient: &http.Client{},
	}
}

type analysisResult struct {
    file           string
    recommendations []string
    err            error
}

// ExtractRepoInfo parses a repository URL to extract owner, repo name, etc.
func ExtractRepoInfo(repoURL string) (provider, owner, repo string, err error) {
	if repoURL == "" {
		return "", "", "", errors.New("empty repository URL")
	}

	parsedURL, err := url.Parse(repoURL)
	if err != nil {
		return "", "", "", err
	}

	hostname := parsedURL.Hostname()
	pathParts := strings.Split(strings.Trim(parsedURL.Path, "/"), "/")

	// Determine provider
	switch hostname {
	case "github.com":
		provider = "github"
	case "gitlab.com":
		provider = "gitlab"
	case "bitbucket.org":
		provider = "bitbucket"
	default:
		return "", "", "", fmt.Errorf("unsupported repository provider: %s", hostname)
	}

	// Basic validation to ensure we have owner and repo parts
	if len(pathParts) < 2 {
		return "", "", "", errors.New("invalid repository URL format")
	}

	owner = pathParts[0]
	repo = pathParts[1]

	// Handle file-specific URLs that contain "blob" or "tree"
	// Example: https://github.com/owner/repo/blob/main/path/to/file.py
	// No need to change owner and repo - we've already extracted them

	return provider, owner, repo, nil
}

// GetFileContent retrieves file content from a repository (improved error handling)
func (s *RepositoryService) GetFileContent(provider, owner, repo, filepath string) (string, error) {
	var apiURL string
	var headers map[string]string

	branch := "main" // Try "main" first
	if provider == "github" {
		mainURL := fmt.Sprintf("https://raw.githubusercontent.com/%s/%s/main/%s", owner, repo, filepath)
		req, _ := http.NewRequest("GET", mainURL, nil)
		resp, err := s.httpClient.Do(req)
		if err == nil && resp.StatusCode == http.StatusOK {
				defer resp.Body.Close()
				content, err := ioutil.ReadAll(resp.Body)
				if err == nil {
						return string(content), nil
				}
		}
		branch = "master" // Fallback to "master"
	}

	switch provider {
	case "github":
		apiURL = fmt.Sprintf("https://raw.githubusercontent.com/%s/%s/%s/%s", owner, repo, branch, filepath)
		headers = map[string]string{}
	case "gitlab":
		apiURL = fmt.Sprintf("https://gitlab.com/api/v4/projects/%s%%2F%s/repository/files/%s/raw?ref=%s",
				owner, repo, url.PathEscape(filepath), branch)
		headers = map[string]string{}
	case "bitbucket":
		apiURL = fmt.Sprintf("https://api.bitbucket.org/2.0/repositories/%s/%s/src/%s/%s",
				owner, repo, branch, filepath)
		headers = map[string]string{}
	default:
		return "", fmt.Errorf("unsupported repository provider: %s", provider)
	}

	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return "", err
	}

	for key, value := range headers {
		req.Header.Set(key, value)
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := ioutil.ReadAll(resp.Body) // Read error body if possible
		return "", fmt.Errorf("failed to fetch file: HTTP %d (URL: %s), Body: %s", resp.StatusCode, apiURL, string(bodyBytes))
	}

	content, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(content), nil
}

func generateTargetedRecommendations(filePath string, ref models.RepoCodeReference, aspects []string, repoDir string) []string {
	recommendations := []string{}

	// 1. Read the file content (with error handling)
	content, err := ioutil.ReadFile(filePath)
	if err != nil {
		log.Printf("Error reading file %s: %v", filePath, err)
		return []string{fmt.Sprintf("Error reading file %s: %v", filePath, err)} // Include error in message
	}

	lines := strings.Split(string(content), "\n")
	totalLines := len(lines)

	// Adjust line numbers if out of range (more robust)
	startLine := ref.LineStart - 1
	endLine := ref.LineEnd - 1

	if startLine < 0 {
		startLine = 0
	}
	if endLine >= totalLines {
		endLine = totalLines - 1
	}

	// 2. Perform targeted analysis
	for _, aspect := range aspects {
		switch strings.ToLower(aspect) {
		case "thoroughness":
			recs := analyze.AnalyzeThoroughnessInLines(filePath, lines, startLine, endLine)
			recommendations = append(recommendations, recs...)
			log.Printf("Thoroughness recommendations for %s (%d-%d): %v", filePath, ref.LineStart, ref.LineEnd, recs)
		case "clarity":
			recs := analyze.AnalyzeClarityInLines(filePath, lines, startLine, endLine)
			recommendations = append(recommendations, recs...)
			log.Printf("Clarity recommendations for %s (%d-%d): %v", filePath, ref.LineStart, ref.LineEnd, recs)
		case "actionability":
			recs := analyze.AnalyzeActionabilityInLines(filePath, lines, startLine, endLine)
			recommendations = append(recommendations, recs...)
			log.Printf("Actionability recommendations for %s (%d-%d): %v", filePath, ref.LineStart, ref.LineEnd, recs)
		}
	}

	return recommendations
}

// handleCodeReviewJSON serves the JSON configuration
func handleCodeReviewJSON(w http.ResponseWriter, r *http.Request) {

	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	filePath := "./integration.json" // Ensure this file exists at root
	byteValue, err := os.ReadFile(filePath)
	if err != nil {
		http.Error(w, "Failed to read analyzer configuration", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(byteValue)
}

func enableCORS(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Set CORS headers
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

		// Handle preflight requests
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		handler(w, r)
	}
}

// cloneOrPullRepo clones a repository or pulls updates if it already exists
func cloneOrPullRepo(provider, owner, repo, repoDir string) error {
    repoURL := ""
    switch provider {
    case "github":
        repoURL = fmt.Sprintf("https://github.com/%s/%s.git", owner, repo)
    case "gitlab":
        repoURL = fmt.Sprintf("https://gitlab.com/%s/%s.git", owner, repo)
    case "bitbucket":
        repoURL = fmt.Sprintf("https://bitbucket.org/%s/%s.git", owner, repo)
    default:
        return fmt.Errorf("unsupported provider: %s", provider) // Correct return type
    }

    log.Printf("Attempting to use repository at: %s", repoDir)

    if _, err := os.Stat(repoDir); os.IsNotExist(err) {
        // Clone the repository with verbose output
        log.Printf("Cloning repository from %s to %s", repoURL, repoDir)
        cmd := exec.Command("git", "clone", repoURL, repoDir)
        output, err := cmd.CombinedOutput()
        if err != nil {
            return fmt.Errorf("failed to clone repository: %w, Output: %s", err, output) // Correct return type
        }
        log.Printf("Successfully cloned %s to %s", repoURL, repoDir)
    } else {
        // Pull updates with better branch handling
        cmd := exec.Command("git", "pull")
        cmd.Dir = repoDir
        output, err := cmd.CombinedOutput()
        if err != nil {
            log.Printf("Pull failed, trying to determine default branch: %s", output)
            // Try to get default branch and pull that instead
            branchCmd := exec.Command("git", "remote", "show", "origin")
            branchCmd.Dir = repoDir
            branchOutput, branchErr := branchCmd.CombinedOutput()
            if branchErr == nil {
                defaultBranch := extractDefaultBranch(string(branchOutput))
                log.Printf("Default branch is: %s", defaultBranch)
                if defaultBranch != "" {
                    log.Printf("Trying pull with default branch: %s", defaultBranch)
                    cmd = exec.Command("git", "pull", "origin", defaultBranch)
                    cmd.Dir = repoDir
                    output, err = cmd.CombinedOutput() // Capture output and error
                    if err != nil {
                        return fmt.Errorf("failed to pull with default branch: %w, Output: %s", err, output)
                    }
                } else {
                    return fmt.Errorf("could not determine default branch")
                }
            } else {
                return fmt.Errorf("failed to get remote info: %w, Output: %s", branchErr, branchOutput)
            }
        }
        log.Printf("Repository at %s is ready", repoDir)
    }

    // Verify the repository has files
    var fileCount int
    err := filepath.Walk(repoDir, func(path string, info os.FileInfo, err error) error {
        if err != nil { // Handle errors during walk
            return err
        }
        if !info.IsDir() {
            fileCount++
        }
        return nil
    })

    if err != nil { // Check for errors after walking
        return fmt.Errorf("error walking repository: %w", err)
    }

    log.Printf("Repository contains %d files", fileCount)

    if fileCount == 0 {
        return fmt.Errorf("repository appears to be empty or inaccessible")
    }

    return nil
}

func extractDefaultBranch(output string) string {
    re := regexp.MustCompile(`HEAD branch: (.+)`)
    matches := re.FindStringSubmatch(output)
    if len(matches) > 1 {
        return matches[1]
    }
    return "main" // Fallback to main
}

func detectLanguage(filename string) string {
	ext := strings.ToLower(filepath.Ext(filename))
	switch ext {
	case ".go":
		return "go"
	case ".php":
		return "php"
	case ".py":
		return "python"
	case ".java":
		return "java"
	case ".js":
		return "javascript"
	case ".jsx":
		return "javascript"
	case ".ts":
		return "typescript"
	case ".tsx":
		return "typescript"
	default: // Add more languages as needed
		return "unknown"
	}
}

// handleCodeReviewAnalysisWithRepo handles code review analysis with repository integration
func handleCodeReviewAnalysisWithRepo(w http.ResponseWriter, r *http.Request) {
    log.Println("Received code review analysis request")
    
    if r.Method != http.MethodPost {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }

    var telexMsg models.TelexMessage
    if err := json.NewDecoder(r.Body).Decode(&telexMsg); err != nil {
        http.Error(w, "Invalid request body", http.StatusBadRequest)
        return
    }

    // Log the received message for debugging
    log.Printf("Received message: %s", telexMsg.Message)
    
    // Extract all settings with proper defaults
    var repoURL string
    codeSource := "github" // Default
    minQualityThreshold := 70.0
    var analysisAspects []string
    includeRecommendations := true

    for _, setting := range telexMsg.Settings {
        switch setting.Label {
        case "repository_url":
            repoURL = setting.Default
        case "code_source":
            codeSource = setting.Default
        case "minimum_quality_threshold":
            threshold, err := strconv.ParseFloat(setting.Default, 64)
            if err == nil {
                minQualityThreshold = threshold
            }
        case "analysis_aspects":
            analysisAspects = strings.Split(setting.Default, ",")
        case "include_recommendations":
            includeRecommendations = setting.Default == "true"
        }
    }

    log.Printf("Analysis settings: repo=%s, source=%s, threshold=%.1f, aspects=%v", 
               repoURL, codeSource, minQualityThreshold, analysisAspects)

    var repoDir string
    var filesToAnalyze []string

    // Handle repository cloning
    if codeSource != "direct" {
        provider, owner, repo, err := ExtractRepoInfo(repoURL)
        if err != nil {
            log.Printf("Error extracting repo info: %v", err)
            http.Error(w, "Invalid repository URL: "+err.Error(), http.StatusBadRequest)
            return
        }
        
        log.Printf("Extracted repo info: provider=%s, owner=%s, repo=%s", provider, owner, repo)

        // *** ALWAYS CLONE A FRESH COPY ***
        tempDir, err := ioutil.TempDir("", "repo-") // Create a temporary directory
        if err != nil {
            log.Printf("Error creating temporary directory: %v", err)
            http.Error(w, "Error accessing repository", http.StatusInternalServerError)
            return
        }
        defer os.RemoveAll(tempDir) // Ensure temporary directory is deleted

        repoDir = filepath.Join(tempDir, fmt.Sprintf("%s-%s", owner, repo)) // Construct repoDir

        err = cloneOrPullRepo(provider, owner, repo, repoDir) // Clone into the temp directory
        if err != nil {
            log.Printf("Error cloning repository: %v", err)
            http.Error(w, fmt.Sprintf("Error accessing repository: %v", err), http.StatusInternalServerError)
            return
        }
        
        log.Printf("Successfully accessed repository at %s", repoDir)

        // Fix for missing ref.Filename issue - we need to modify this part
        // Instead of using ref.Filename, let's scan the entire repository
        log.Printf("Scanning entire repository")
        err = filepath.Walk(repoDir, func(path string, info os.FileInfo, err error) error {
            if err != nil {
                return err
            }
            if !info.IsDir() {
                lang := detectLanguage(path)
                if lang != "unknown" {
                    filesToAnalyze = append(filesToAnalyze, path)
                    if len(filesToAnalyze) <= 5 { // Log only first few files
                        log.Printf("Adding file for analysis: %s (lang: %s)", path, lang)
                    }
                }
            }
            return nil
        })
        
        log.Printf("Found %d files to analyze in repository", len(filesToAnalyze))
        
        if err != nil {
            log.Printf("Error walking repo directory: %v", err)
            http.Error(w, fmt.Sprintf("Error scanning repository: %v", err), http.StatusInternalServerError)
            return
        }
    } else {
        // Direct code analysis path would be here
        // (Keeping this simple for the fix)
        log.Printf("Direct code analysis not implemented fully")
    }

    // 2. Analyze Code
    allRecommendations := []string{}
	analyzedFiles := []string{}
	totalFilesAnalyzed := 0
    totalQualityScore := 0.0

	if len(filesToAnalyze) == 0 {
        log.Printf("No files to analyze!")
        totalFilesAnalyzed = 0                                                  // No files analyzed
	} else {
		var wg sync.WaitGroup // Wait group for goroutines
		results := make(chan analysisResult) // Channel for analysis results

		for _, file := range filesToAnalyze {
			wg.Add(1)
			go func(file string) { // Goroutine for each file
				defer wg.Done()
				recs, err := analyzeFile(file, repoDir, analysisAspects) // Analyze single file
				results <- analysisResult{file: file, recommendations: recs, err: err} // Send results
			}(file)
		}

		go func() {
			wg.Wait()
			close(results) // Close channel when all goroutines are done
		}()

		for result := range results { // Process results as they come in
			if result.err != nil {
				log.Printf("Error analyzing %s: %v", result.file, result.err)
				allRecommendations = append(allRecommendations, fmt.Sprintf("## %s\n- Error during analysis: %v", result.file, result.err))
				continue
			}

			if len(result.recommendations) > 0 {
				displayPath := result.file
				if repoDir != "" && strings.HasPrefix(result.file, repoDir) {
					displayPath = strings.TrimPrefix(result.file, repoDir)
					displayPath = strings.TrimPrefix(displayPath, "/")
				}
				analyzedFiles = append(analyzedFiles, displayPath)
				allRecommendations = append(allRecommendations, fmt.Sprintf("## %s\n", displayPath))
				for _, rec := range result.recommendations {
					allRecommendations = append(allRecommendations, fmt.Sprintf("- %s", rec))
				}

				fileMetrics := calculateFileMetrics(result.recommendations, analysisAspects)
				totalQualityScore += fileMetrics.OverallQuality
				totalFilesAnalyzed++
			}
		}
	}

    // Generate response
    var codeAnalysisResponse strings.Builder
    codeAnalysisResponse.WriteString("## Code Analysis Results\n\n")
    
    if len(analyzedFiles) > 0 {
        codeAnalysisResponse.WriteString("### Analyzed Files:\n")
        for _, file := range analyzedFiles {
            codeAnalysisResponse.WriteString(fmt.Sprintf("- %s\n", file))
        }
        codeAnalysisResponse.WriteString("\n")
    }

    if len(allRecommendations) > 0 {
        codeAnalysisResponse.WriteString("### Recommendations:\n")
        for _, rec := range allRecommendations {
            codeAnalysisResponse.WriteString(rec + "\n")
        }
    } else {
        codeAnalysisResponse.WriteString("No issues found in the analyzed files.\n")
    }

    // Analyze the code review itself
    metrics := analyzeCodeReview(telexMsg.Message, analysisAspects)
    log.Printf("Review quality metrics: %+v", metrics)

    trends := getHistoricalTrends(telexMsg.ChannelID)

    response := generateEnhancedResponse(metrics, includeRecommendations, trends)
    
    message := map[string]string{
        "event_name": "Code Review Analysis",
        "message":    codeAnalysisResponse.String() + response,
        "status":     "success",
        "username":   "Code Review Analyzer",
    }

    if repoDir != "" {
        // In production, you might want this. For debugging, comment it out
        os.RemoveAll(repoDir) // Clean up the repository directory
        log.Printf("Repository directory removed: %s", repoDir)
    }
    
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(message)
}

func analyzeFile(file, repoDir string, analysisAspects []string) ([]string, error) {
    lang := detectLanguage(file)
    log.Printf("Analyzing file: %s (language: %s)", file, lang)

    content, err := ioutil.ReadFile(file)
    if err != nil {
        return nil, fmt.Errorf("error reading file %s: %w", file, err)
    }

    displayPath := file
    if repoDir != "" && strings.HasPrefix(file, repoDir) {
        displayPath = strings.TrimPrefix(file, repoDir)
        displayPath = strings.TrimPrefix(displayPath, "/")
    }

    var allRecs []string
    
    // Base analysis for each aspect
    for _, aspect := range analysisAspects {
        var aspectRecs []string
        
        switch strings.ToLower(aspect) {
        case "thoroughness":
            aspectRecs = analyzeThoroughnessForFile(displayPath, string(content), lang)
        case "clarity":
            aspectRecs = analyzeClarityForFile(displayPath, string(content), lang)
        case "actionability":
            aspectRecs = analyzeActionabilityForFile(displayPath, string(content), lang)
        }
        
        allRecs = append(allRecs, aspectRecs...)
    }

    // Language-specific analysis
    var langRecs []string
    var langErr error
    
    switch lang {
    case "go":
        langRecs, langErr = analyze.AnalyzeGoCode(displayPath, string(content))
    case "php":
        langRecs, langErr = analyze.AnalyzePHPCode(displayPath, string(content))
    case "python":
        langRecs, langErr = analyze.AnalyzePythonCode(displayPath, string(content))
    case "java":
        langRecs, langErr = analyze.AnalyzeJavaCode(displayPath, string(content))
    default:
        return allRecs, nil // Return aspect-based recommendations for unsupported languages
    }

    if langErr != nil {
        // Don't return error, just log it and continue with aspect-based recommendations
        log.Printf("Language-specific analysis error for %s: %v", displayPath, langErr)
        return allRecs, nil
    }

    allRecs = append(allRecs, langRecs...)
    return allRecs, nil
}

// New helper functions for aspect-based analysis

func analyzeThoroughnessForFile(filepath, content, lang string) []string {
    var recs []string
    
    // Check for documentation
    if !hasAdequateDocumentation(content, lang) {
        recs = append(recs, fmt.Sprintf("Add more documentation to %s to improve code understanding", filepath))
    }
    
    // Check for error handling
    if !hasAdequateErrorHandling(content, lang) {
        recs = append(recs, fmt.Sprintf("Improve error handling in %s", filepath))
    }
    
    // Check for test coverage (if it's not a test file)
    if !strings.Contains(strings.ToLower(filepath), "test") && !hasTestFile(filepath) {
        recs = append(recs, fmt.Sprintf("Create unit tests for %s", filepath))
    }
    
    // Check for complex functions
    if complexFunctions := findComplexFunctions(content, lang); len(complexFunctions) > 0 {
        recs = append(recs, fmt.Sprintf("Consider breaking down complex functions in %s: %s", 
            filepath, strings.Join(complexFunctions, ", ")))
    }
    
    return recs
}

func analyzeClarityForFile(filepath, content, lang string) []string {
    var recs []string
    
    // Check naming conventions
    if badNames := findPoorlyNamedElements(content, lang); len(badNames) > 0 {
        recs = append(recs, fmt.Sprintf("Improve naming clarity in %s for: %s", 
            filepath, strings.Join(badNames, ", ")))
    }
    
    // Check code structure
    if !hasGoodStructure(content, lang) {
        recs = append(recs, fmt.Sprintf("Improve code structure and organization in %s", filepath))
    }
    
    // Check for overly complex expressions
    if complexExpr := findComplexExpressions(content); len(complexExpr) > 0 {
        recs = append(recs, fmt.Sprintf("Simplify complex expressions in %s", filepath))
    }
    
    return recs
}

func analyzeActionabilityForFile(filepath, content, lang string) []string {
    var recs []string
    
    // Check for TODO comments
    if todos := findTodoComments(content); len(todos) > 0 {
        recs = append(recs, fmt.Sprintf("Address TODO comments in %s", filepath))
    }
    
    // Check for deprecated features
    if deprecated := findDeprecatedUsage(content, lang); len(deprecated) > 0 {
        recs = append(recs, fmt.Sprintf("Update deprecated features in %s: %s", 
            filepath, strings.Join(deprecated, ", ")))
    }
    
    // Check for potential improvements
    if improvements := findPotentialImprovements(content, lang); len(improvements) > 0 {
        recs = append(recs, improvements...)
    }
    
    return recs
}

// Helper functions for analysis

func hasAdequateDocumentation(content, lang string) bool {
    switch lang {
    case "python":
        docstrings := regexp.MustCompile(`"""[\s\S]*?"""|'''[\s\S]*?'''`).FindAllString(content, -1)
        return len(docstrings) > 0
    case "go":
        comments := regexp.MustCompile(`//.*|/\*[\s\S]*?\*/`).FindAllString(content, -1)
        return len(comments) > 0
    default:
        return true // Default to true for unsupported languages
    }
}

func hasAdequateErrorHandling(content, lang string) bool {
    switch lang {
    case "python":
        return strings.Contains(content, "try:") && strings.Contains(content, "except")
    case "go":
        return strings.Contains(content, "if err != nil")
    default:
        return true
    }
}

func hasTestFile(filepath string) bool {
    testPath := strings.Replace(filepath, ".py", "_test.py", 1)
    testPath = strings.Replace(testPath, ".go", "_test.go", 1)
    _, err := os.Stat(testPath)
    return err == nil
}

func findComplexFunctions(content, lang string) []string {
    var complex []string
    // Simplified complexity check - looking for nested loops/conditions
    switch lang {
    case "python":
        if matches := regexp.MustCompile(`def\s+(\w+)[^{]*?:`).FindAllStringSubmatch(content, -1); matches != nil {
            for _, match := range matches {
                if strings.Count(match[0], "    ") > 2 { // Check indentation level
                    complex = append(complex, match[1])
                }
            }
        }
    case "go":
        if matches := regexp.MustCompile(`func\s+(\w+)[^{]*?{`).FindAllStringSubmatch(content, -1); matches != nil {
            for _, match := range matches {
                if strings.Count(match[0], "for") > 1 || strings.Count(match[0], "if") > 2 {
                    complex = append(complex, match[1])
                }
            }
        }
    }
    return complex
}

func findPoorlyNamedElements(content, lang string) []string {
    var poorNames []string
    // Look for single-letter variables and unclear names
    switch lang {
    case "python", "go":
        vars := regexp.MustCompile(`\b[a-z_]+\b`).FindAllString(content, -1)
        for _, v := range vars {
            if len(v) == 1 || strings.Contains(v, "temp") || strings.Contains(v, "tmp") {
                poorNames = append(poorNames, v)
            }
        }
    }
    return poorNames
}

func hasGoodStructure(content, lang string) bool {
    // Basic structure checks
    switch lang {
    case "python":
        // Check for consistent indentation and class/function organization
        return !strings.Contains(content, "\t") // Python should use spaces
    case "go":
        // Check for package organization and proper formatting
        return strings.HasPrefix(content, "package ") && !strings.Contains(content, "\t\t\t\t")
    default:
        return true
    }
}

func findComplexExpressions(content string) []string {
    var complex []string
    // Look for long lines and nested expressions
    lines := strings.Split(content, "\n")
    for _, line := range lines {
        if len(line) > 100 || strings.Count(line, "&&") > 2 || strings.Count(line, "||") > 2 {
            complex = append(complex, "Long or complex expression found")
            break
        }
    }
    return complex
}

func findTodoComments(content string) []string {
    todos := regexp.MustCompile(`(?i)//\s*TODO|#\s*TODO|/\*\s*TODO`).FindAllString(content, -1)
    return todos
}

func findDeprecatedUsage(content, lang string) []string {
    var deprecated []string
    switch lang {
    case "python":
        if strings.Contains(content, "print ") || strings.Contains(content, "urllib2") {
            deprecated = append(deprecated, "print statement (use print())", "urllib2 (use requests)")
        }
    case "go":
        if strings.Contains(content, "ioutil.") {
            deprecated = append(deprecated, "ioutil (use io/fs)")
        }
    }
    return deprecated
}

func findPotentialImprovements(content, lang string) []string {
    var improvements []string
    
    // Generic improvements
    if strings.Count(content, "\n") > 300 {
        improvements = append(improvements, "Consider breaking this file into smaller modules")
    }
    
    // Language-specific improvements
    switch lang {
    case "python":
        if !strings.Contains(content, "typing.") && !strings.Contains(content, "from typing import") {
            improvements = append(improvements, "Consider adding type hints for better code maintainability")
        }
    case "go":
        if strings.Contains(content, "var ") && !strings.Contains(content, ":=") {
            improvements = append(improvements, "Consider using := for shorter variable declarations where appropriate")
        }
    }
    
    return improvements
}

// *** NEW FUNCTION: Calculate file metrics from recommendations ***
func calculateFileMetrics(recs []string, aspects []string) models.CodeReviewMetrics {
    metrics := models.CodeReviewMetrics{}
    aspectScores := make(map[string]float64) // Store aspect scores

    for _, aspect := range aspects {
        score := 0.0

        switch strings.ToLower(aspect) {
        case "thoroughness":
            score = calculateAspectScore(recs, "thoroughness") // Helper function
        case "clarity":
            score = calculateAspectScore(recs, "clarity")      // Helper function
        case "actionability":
            score = calculateAspectScore(recs, "actionability") // Helper function
        }
        aspectScores[aspect] = score
        // Directly set metrics (no need to sum first)
        switch strings.ToLower(aspect) {
        case "thoroughness":
            metrics.Thoroughness = score
        case "clarity":
            metrics.Clarity = score
        case "actionability":
            metrics.Actionability = score
        }
    }

    // Calculate overall quality based on selected aspects
    totalScore := 0.0
    validAspectCount := 0

    for _, aspect := range aspects {
        totalScore += aspectScores[aspect]
        validAspectCount++
    }

    if validAspectCount > 0 {
        metrics.OverallQuality = totalScore / float64(validAspectCount)
    }

    return metrics
}

// *** NEW HELPER FUNCTION: Calculate score for a specific aspect ***
func calculateAspectScore(recs []string, aspect string) float64 {
    score := 0.0

    for _, rec := range recs {
        recLower := strings.ToLower(rec)

        switch aspect {
        case "thoroughness":
            keywords := []string{"performance", "security", "scalability", "maintainability", "testing", "edge case", "complexity", "algorithm", "pattern", "readability", "efficiency", "memory", "time complexity", "space complexity"}
            for _, keyword := range keywords {
                if strings.Contains(recLower, keyword) {
                    score += 1.0 // Adjust weight as needed
                }
            }
        case "clarity":
            keywords := []string{"clear", "concise", "understandable", "readable", "well-documented", "simple", "consistent"}
            for _, keyword := range keywords {
                if strings.Contains(recLower, keyword) {
                    score += 1.0
                }
            }
        case "actionability":
            keywords := []string{"fix", "improve", "change", "refactor", "optimize", "add", "remove", "implement", "consider", "suggest", "recommend"}
            for _, keyword := range keywords {
                if strings.Contains(recLower, keyword) {
                    score += 1.0
                }
            }
        }
    }

    return score // Adjust normalization as needed (e.g., divide by max possible score)
}

// Regular expression to extract code references (improved format and case-insensitive)
// var codeReferenceRegex = regexp.MustCompile(`(?i)([\w.-/]+):(\d+)(?:-(\d+))?`) // Improved regex, added / for paths

func analyzeCodeReview(comment string, aspects []string) models.CodeReviewMetrics {
    metrics := models.CodeReviewMetrics{
        Recommendations: []string{},
    }

    // Initialize base scores even without references
    if comment == "" {
        metrics.Recommendations = append(metrics.Recommendations, 
            "No review comment provided. Please add detailed comments about the code.")
        return metrics
    }

    // Calculate base metrics from the comment itself
    for _, aspect := range aspects {
        switch strings.ToLower(aspect) {
        case "thoroughness":
            metrics.Thoroughness = analyzeThoroughness(comment)
        case "clarity":
            metrics.Clarity = analyzeClarity(comment)
        case "actionability":
            metrics.Actionability = analyzeActionability(comment)
        }
    }

    // Calculate initial overall quality from comment analysis
    aspectCount := 0
    aspectSum := 0.0
    if metrics.Thoroughness > 0 {
        aspectSum += metrics.Thoroughness
        aspectCount++
    }
    if metrics.Clarity > 0 {
        aspectSum += metrics.Clarity
        aspectCount++
    }
    if metrics.Actionability > 0 {
        aspectSum += metrics.Actionability
        aspectCount++
    }

    if aspectCount > 0 {
        metrics.OverallQuality = aspectSum / float64(aspectCount)
    }

    // Ensure minimum quality score based on meaningful content
    if len(strings.Split(comment, " ")) > 10 && metrics.OverallQuality < 30 {
        metrics.OverallQuality = 30 // Set minimum score for meaningful comments
    }

    return metrics
}

func analyzeThoroughness(comment string) float64 {
    if comment == "" {
        return 0
    }

    score := 30.0 // Base score for providing any review
    maxScore := 100.0

    // Check for specific file mentions
    fileRefs := regexp.MustCompile(`(?i)[\/\\]?[\w-]+\.(py|js|go|java|cpp|ts|jsx|tsx)`).FindAllString(comment, -1)
    score += math.Min(float64(len(fileRefs))*10.0, 20.0)

    // Check for specific code elements
    codeElements := regexp.MustCompile(`(?i)(class|function|method|variable|import|module)\s+\w+`).FindAllString(comment, -1)
    score += math.Min(float64(len(codeElements))*5.0, 15.0)

    // Check for technical depth
    technicalTerms := []string{
        "performance", "security", "scalability", "maintainability",
        "testing", "edge case", "error handling", "validation",
        "documentation", "optimization", "dependency", "interface",
    }
    
    technicalScore := 0.0
    for _, term := range technicalTerms {
        if strings.Contains(strings.ToLower(comment), term) {
            technicalScore += 5.0
        }
    }
    score += math.Min(technicalScore, 25.0)

    // Normalize score
    return math.Min(score, maxScore)
}

func analyzeClarity(comment string) float64 {
	score := 0.0
	maxScore := 10.0

	paragraphs := strings.Count(comment, "\n\n") + 1
	structureScore := math.Min(float64(paragraphs)*0.7, 2.0)

	bulletPoints := regexp.MustCompile(`(?m)^[\s]*[•\-\*]\s`).FindAllString(comment, -1)
	numberedPoints := regexp.MustCompile(`(?m)^[\s]*\d+[\.)]\s`).FindAllString(comment, -1)
	listScore := math.Min(float64(len(bulletPoints)+len(numberedPoints))*0.5, 2.0)

	score += math.Max(structureScore, listScore)

	explanationTerms := regexp.MustCompile(`because|since|as|therefore|consequently|this means|in order to|which leads to|resulting in`)
	explanationMatches := explanationTerms.FindAllString(strings.ToLower(comment), -1)
	explanationScore := math.Min(float64(len(explanationMatches))*0.8, 2.5)
	score += explanationScore

	codeExamples := regexp.MustCompile("```[^`]*```|`[^`]+`").FindAllString(comment, -1)
	codeScore := math.Min(float64(len(codeExamples))*1.0, 2.5)
	score += codeScore

	comparativeTerms := regexp.MustCompile(`instead of|rather than|compared to|current|suggested|alternative|better approach|improvement`)
	comparativeMatches := comparativeTerms.FindAllString(strings.ToLower(comment), -1)
	comparativeScore := math.Min(float64(len(comparativeMatches))*0.5, 1.5)
	score += comparativeScore

	sentences := regexp.MustCompile(`[.!?]+\s+|\n`).Split(comment, -1)
	longSentences := 0
	for _, sentence := range sentences {
		words := strings.Fields(sentence)
		if len(words) > 25 {
			longSentences++
		}
	}
	readabilityScore := 1.5 - math.Min(float64(longSentences)*0.5, 1.5)
	score += readabilityScore

	return (score / maxScore) * 100
}

func analyzeActionability(comment string) float64 {
	score := 0.0
	maxScore := 10.0

	suggestionTerms := regexp.MustCompile(`(?i)suggest|consider|recommend|try|could|should|need to|must|important to|better to|preferable|advised`)
	suggestionMatches := suggestionTerms.FindAllString(comment, -1)
	suggestionScore := math.Min(float64(len(suggestionMatches))*0.6, 2.5)
	score += suggestionScore

	inlineCode := regexp.MustCompile("`[^`]+`").FindAllString(comment, -1)
	blockCode := regexp.MustCompile("```[^`]*```").FindAllString(comment, -1)
	codeScore := math.Min(float64(len(inlineCode))*0.7+float64(len(blockCode))*1.5, 3.0)
	score += codeScore

	actionItems := regexp.MustCompile(`(?i)(?:^|\n)\s*(?:\d+[.)\s]+|\*\s+|[-•]\s+)(?:.*?(?:move|add|remove|refactor|rename|extract|inline|implement|fix|update|change|simplify|optimize|delete|rewrite|convert|prevent|handle|include|exclude|ensure|verify|check|confirm|validate)[^.!?\n]*)`).FindAllString(comment, -1)
	todoItems := regexp.MustCompile(`(?i)TODO:|FIXME:|BUG:|ISSUE:`).FindAllString(comment, -1)
	actionScore := math.Min(float64(len(actionItems))*0.8+float64(len(todoItems))*1.0, 2.5)
	score += actionScore

	implementationDetails := regexp.MustCompile(`(?i)implement using|change to|replace with|switch to|move from|convert to|transform into|use the|apply the|following syntax|pattern|approach`).FindAllString(comment, -1)
	implScore := math.Min(float64(len(implementationDetails))*0.6, 2.0)
	score += implScore

	return (score / maxScore) * 100
}

func generateResponse(metrics models.CodeReviewMetrics, includeRecommendations bool) string { // Removed threshold
    getQualityEmoji := func(score float64) string {
        if score >= 85 {
            return "🟢"
        } else if score >= 70 { // Fixed threshold
            return "🟡"
        } else {
            return "🔴"
        }
    }

    response := "## Code Review Quality Analysis\n\n"

    if metrics.Thoroughness > 0 {
        response += fmt.Sprintf("%s **Thoroughness**: %.1f%%\n", getQualityEmoji(metrics.Thoroughness), metrics.Thoroughness)
    }

    if metrics.Clarity > 0 {
        response += fmt.Sprintf("%s **Clarity**: %.1f%%\n", getQualityEmoji(metrics.Clarity), metrics.Clarity)
    }

    if metrics.Actionability > 0 {
        response += fmt.Sprintf("%s **Actionability**: %.1f%%\n", getQualityEmoji(metrics.Actionability), metrics.Actionability)
    }

    if metrics.OverallQuality >= 70 { // Fixed threshold
        response += fmt.Sprintf("\n✅ **Meets quality threshold** (70.0%%)\n")
    } else {
        response += fmt.Sprintf("\n⚠️ **Below quality threshold** (70.0%%)\n")
    }

    if includeRecommendations && len(metrics.Recommendations) > 0 {
        response += "\n### Recommendations for Improvement\n"
        for _, rec := range metrics.Recommendations {
            response += fmt.Sprintf("- %s\n", rec)
        }
    }

    return response
}

var analysisHistoriesMutex sync.RWMutex // Add mutex for concurrent access

func init() {
    // Start a goroutine to clear the cache every 24 hours
    go func() {
        for range time.Tick(24 * time.Hour) {
            analysisHistoriesMutex.Lock()
            analysisHistories = make(map[string][]models.AnalysisHistory) // Clear the map
            analysisHistoriesMutex.Unlock()
            fmt.Println("Analysis history cache cleared.")
        }
    }()
}

// Function to get historical trends (using in-memory cache)
func getHistoricalTrends(channelID string) []models.AnalysisHistory {
    analysisHistoriesMutex.RLock() // Read lock
    history := analysisHistories[channelID]
    analysisHistoriesMutex.RUnlock()

	return history
}

// Enhanced response generator with trend information
func generateEnhancedResponse(metrics models.CodeReviewMetrics, includeRecommendations bool, trends []models.AnalysisHistory) string {
    baseResponse := generateResponse(metrics, includeRecommendations)

    if len(trends) > 0 {  // Check if there's any history
        // Calculate average quality
        totalQuality := 0.0
        for _, entry := range trends {
            totalQuality += entry.OverallQuality
        }
        averageQuality := totalQuality / float64(len(trends))

        // Calculate trend (simple linear regression - improved handling of short history)
        recent := trends
        if len(trends) > 10 { // Use last 10 if available, otherwise use all
            recent = trends[len(trends)-10:]
        }

        trendChange := 0.0
        if len(recent) >= 2 {
            firstQuality := recent[0].OverallQuality
            lastQuality := recent[len(recent)-1].OverallQuality
            trendChange = lastQuality - firstQuality
        }

        trendEmoji := "➡️"
        if trendChange > 5 {
            trendEmoji = "📈"
        } else if trendChange < -5 {
            trendEmoji = "📉"
        }

        trendResponse := fmt.Sprintf("\n### Historical Perspective\n%s Quality trend: ", trendEmoji)
        if math.Abs(trendChange) < 2 {
            trendResponse += "Stable"
        } else if trendChange > 0 {
            trendResponse += fmt.Sprintf("Improving (+%.1f%%)", trendChange) // Show % change
        } else {
            trendResponse += fmt.Sprintf("Declining (%.1f%%)", math.Abs(trendChange)) // Show % change
        }

        comparisonEmoji := "➡️"
        diff := metrics.OverallQuality - averageQuality
        if diff > 5 {
            comparisonEmoji = "🌟"
        } else if diff < -5 {
            comparisonEmoji = "⚠️"
        }

        trendResponse += fmt.Sprintf("\n%s Compared to average: ", comparisonEmoji)
        if math.Abs(diff) < 2 {
            trendResponse += "On par with typical reviews"
        } else if diff > 0 {
            trendResponse += fmt.Sprintf("Above average (+%.1f%%)", diff) // Show % difference
        } else {
            trendResponse += fmt.Sprintf("Below average (%.1f%%)", math.Abs(diff)) // Show % difference
        }

        return baseResponse + trendResponse
    }
    return baseResponse
}

func main() {
	// Set up HTTP server
	http.HandleFunc("/analyze", enableCORS(handleCodeReviewAnalysisWithRepo))
	http.HandleFunc("/integration-json", enableCORS(handleCodeReviewJSON))

	// Serve static files from the "static" directory
	fs := http.FileServer(http.Dir("static"))
	http.Handle("/static/", http.StripPrefix("/static/", fs))

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	log.Printf("Server running on port %s", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}