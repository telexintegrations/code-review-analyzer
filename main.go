package main

import (
	// "bytes"
	// "encoding/base64"
	"context"
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

// ExtractCodeReferences extracts code references from a comment (improved regex and handling)
func ExtractCodeReferences(comment string) []models.RepoCodeReference {
	var refs []models.RepoCodeReference
	matches := codeReferenceRegex.FindAllStringSubmatch(comment, -1)
	for _, match := range matches {
		log.Printf("Match: %v", match)
		if len(match) >= 3 {
			filename := match[1]
			startLine, _ := strconv.Atoi(match[2])
			endLine := startLine // Default if no end line
			if len(match) >= 4 && match[3] != "" {
				endLine, _ = strconv.Atoi(match[3])
			}
			refs = append(refs, models.RepoCodeReference{
				Filename:  filename,
				LineStart: startLine,
				LineEnd:   endLine,
			})
		}
	}
	return refs
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

// EnhanceCodeReviewWithContext adds repository context to code review comments
func (s *RepositoryService) EnhanceCodeReviewWithContext(comment, provider, owner, repo string) (string, error) {
	refs := ExtractCodeReferences(comment)
	if len(refs) == 0 {
		return comment, nil
	}

	var enhancedComment strings.Builder
	enhancedComment.WriteString(comment)
	enhancedComment.WriteString("\n\n")

	for _, ref := range refs {
		content, err := s.GetFileContent(provider, owner, repo, ref.Filename)
		if err != nil {
			enhancedComment.WriteString(fmt.Sprintf("Context for %s (lines %d-%d): File not found or error retrieving context.\n\n", ref.Filename, ref.LineStart, ref.LineEnd))
			continue
		}

		enhancedComment.WriteString(fmt.Sprintf("Context for %s (lines %d-%d):\n```\n",
				ref.Filename, ref.LineStart, ref.LineEnd))

		lines := strings.Split(content, "\n")
		startLine := max(0, ref.LineStart-5)
		endLine := min(len(lines), ref.LineEnd+5)

		for i := startLine; i < endLine && i < len(lines); i++ {
			lineNum := i + 1
			enhancedComment.WriteString(fmt.Sprintf("%d: %s\n", lineNum, lines[i]))
		}

		enhancedComment.WriteString("```\n\n")
	}

	return enhancedComment.String(), nil
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

func extractDefaultBranch(remoteShowOutput string) string {
    lines := strings.Split(remoteShowOutput, "\n")
    for _, line := range lines {
        if strings.HasPrefix(line, "  HEAD branch:") {
            parts := strings.Fields(line)
            if len(parts) > 2 {
                return parts[2]
            }
        }
    }
    return ""
}

// Helper function to extract default branch name
/* func extractDefaultBranch(output string) string {
    re := regexp.MustCompile(`HEAD branch: (.+)`)
    matches := re.FindStringSubmatch(output)
    if len(matches) > 1 {
        return matches[1]
    }
    return "main" // Fallback to main
} */

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

        // Find code references in the review comment
        refs := ExtractCodeReferences(telexMsg.Message)
        log.Printf("Found %d code references in comment", len(refs))
        
        if len(refs) > 0 {
            // If we have specific references, analyze only those files
            for _, ref := range refs {
                fullPath := filepath.Join(repoDir, ref.Filename) // Use repoDir!
                if _, err := os.Stat(fullPath); err == nil {
                    filesToAnalyze = append(filesToAnalyze, fullPath)
                    log.Printf("Will analyze referenced file: %s", fullPath)
                } else {
                    log.Printf("Referenced file not found: %s (error: %v)", fullPath, err)
                    matches, _ := findSimilarFiles(repoDir, ref.Filename) // Use repoDir!
                    for _, match := range matches {
                        filesToAnalyze = append(filesToAnalyze, match)
                        log.Printf("Found similar file: %s", match)
                    }
                }
            }
        }
        
        // If no specific files were referenced or found, analyze all applicable files
        if len(filesToAnalyze) == 0 {
            log.Printf("No specific files referenced, will scan entire repository")
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
        allRecommendations = append(allRecommendations, "No analyzable files found. Check file types and existence.")
        metrics := analyzeCodeReview(telexMsg.Message, analysisAspects, repoDir) // Analyze comment
        // totalQualityScore = metrics.OverallQuality                               // Use comment quality
        totalFilesAnalyzed = 0                                                  // No files analyzed
        overallQuality := metrics.OverallQuality // Correctly set overallQuality here!

        // Generate response *before* returning to avoid race conditions
        codeAnalysisResponse := generateCodeAnalysisResponse(analyzedFiles, allRecommendations)
        trackAnalysisHistory(telexMsg.ChannelID, metrics, len(telexMsg.Message))
        trends := getHistoricalTrends(telexMsg.ChannelID)
        response := generateEnhancedResponse(metrics, includeRecommendations, trends)

        message := map[string]string{
            "event_name": "message_formatted",
            "message":    codeAnalysisResponse + response,
            "status":     getQualityStatus(overallQuality), // Use overallQuality here
            "username":   "Code Review Analyzer",
        }

        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(message)

        if repoDir != "" {
            log.Printf("Repository directory preserved for debugging: %s", repoDir)
        }
        return // Important: Return here to avoid further processing                                                 // No files analyzed
	}

	// Parallel analysis of files
    var wg sync.WaitGroup
    results := make(chan analysisResult)
    ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second) // 5-second timeout
    defer cancel()

    for _, file := range filesToAnalyze {
        wg.Add(1)
        go func(file string) {
            defer wg.Done()
            recs, err := analyzeFile(file, repoDir, analysisAspects)
            select {
            case <-ctx.Done():
                results <- analysisResult{file: file, err: ctx.Err()} // Send timeout error
            default:
                results <- analysisResult{file: file, recommendations: recs, err: err}
            }
        }(file)
    }

    go func() {
        wg.Wait()
        close(results)
    }()

    for result := range results {
        if result.err != nil {
            log.Printf("Error analyzing %s: %v", result.file, result.err)
            allRecommendations = append(allRecommendations, fmt.Sprintf("## %s\n- Error during analysis: %v", result.file, result.err))
            continue
        }

        if len(result.recommendations) > 0 {
            displayPath := result.file
            if repoDir != "" && strings.HasPrefix(result.file, repoDir) {
                displayPath = strings.TrimPrefix(displayPath, repoDir)
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

    overallQuality := 0.0
    if totalFilesAnalyzed > 0 {
        overallQuality = totalQualityScore / float64(totalFilesAnalyzed)
    } else {
        metrics := analyzeCodeReview(telexMsg.Message, analysisAspects, repoDir)
        overallQuality = metrics.OverallQuality

		// *** Default quality if analyzeCodeReview still returns 0 ***
        if overallQuality == 0.0 {
            overallQuality = 50.0 // Or any other suitable default
            log.Println("WARNING: analyzeCodeReview returned 0.0 for comment analysis. Using default quality score.")
        }
    }

    codeAnalysisResponse := generateCodeAnalysisResponse(analyzedFiles, allRecommendations)

    metrics := analyzeCodeReview(telexMsg.Message, analysisAspects, repoDir) // Analyze code review comment
    trackAnalysisHistory(telexMsg.ChannelID, metrics, len(telexMsg.Message))
    trends := getHistoricalTrends(telexMsg.ChannelID)

    response := generateEnhancedResponse(metrics, includeRecommendations, trends)

    message := map[string]string{
        "event_name": "message_formatted",
        "message":    codeAnalysisResponse + response,
        "status":     getQualityStatus(overallQuality), // Use overallQuality here
        "username":   "Code Review Analyzer",
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(message)

    if repoDir != "" {
        log.Printf("Repository directory preserved for debugging: %s", repoDir)
    }
}

func generateCodeAnalysisResponse(analyzedFiles, allRecommendations []string) string {
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
    return codeAnalysisResponse.String()
}

func analyzeFile(file, repoDir string, analysisAspects []string) ([]string, error) {
    lang := detectLanguage(file)
    log.Printf("Analyzing file: %s (language: %s)", file, lang)

    var recs []string
    var err error

    content, err := ioutil.ReadFile(file)
    if err != nil {
        return nil, fmt.Errorf("error reading file %s: %w", file, err)
    }

    displayPath := file
    if repoDir != "" && strings.HasPrefix(file, repoDir) {
        displayPath = strings.TrimPrefix(file, repoDir)
        displayPath = strings.TrimPrefix(displayPath, "/")
    }

    switch lang {
    case "go":
        recs, err = analyze.AnalyzeGoCode(displayPath, string(content))
    case "php":
        recs, err = analyze.AnalyzePHPCode(displayPath, string(content))
    case "python":
        recs, err = analyze.AnalyzePythonCode(displayPath, string(content))
    case "java":
        recs, err = analyze.AnalyzeJavaCode(displayPath, string(content))
    // ... other languages
    default:
        return nil, fmt.Errorf("language not supported: %s", lang)
    }

    return recs, err
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

// Helper function to find files with similar names
func findSimilarFiles(rootDir, targetFile string) ([]string, error) {
    targetLower := strings.ToLower(targetFile)
    ext := filepath.Ext(targetLower)
    
    var matches []string
    err := filepath.Walk(rootDir, func(path string, info os.FileInfo, err error) error {
        if err != nil {
            return err
        }
        if !info.IsDir() {
            pathLower := strings.ToLower(path)
            // Match by extension and contains the base filename
            if strings.HasSuffix(pathLower, ext) && 
               strings.Contains(pathLower, strings.TrimSuffix(filepath.Base(targetLower), ext)) {
                matches = append(matches, path)
            }
        }
        return nil
    })
    
    return matches, err
}

func getQualityStatus(overallQuality float64) string {
    threshold := 70.0 // Fixed threshold

    if overallQuality < threshold {
        return "Inadequate"
    } else if overallQuality < 85 {
        return "Acceptable"
    } else {
        return "Excellent"
    }
}

// Regular expression to extract code references (improved format and case-insensitive)
var codeReferenceRegex = regexp.MustCompile(`(?i)([\w.-/]+):(\d+)(?:-(\d+))?`) // Improved regex, added / for paths

func analyzeCodeReview(comment string, aspects []string, repoDir string) models.CodeReviewMetrics { // Add repoDir
	metrics := models.CodeReviewMetrics{
		Recommendations: []string{},
	}
	
	refs := ExtractCodeReferences(comment) // Extract code references from the comment
	log.Printf("Found %d code references in comment", len(refs))

	if len(refs) == 0 {
        metrics.Recommendations = append(metrics.Recommendations, "No specific code references found. General review based on comment.")
        // Calculate overall quality based on comment analysis
        if len(aspects) > 0 {
            totalAspectScore := metrics.Thoroughness + metrics.Clarity + metrics.Actionability
            metrics.OverallQuality = totalAspectScore / float64(len(aspects))
        } else {
            metrics.OverallQuality = 0 // If no aspects are selected, it can be 0.
        }
        return metrics
    }

	aspectCount := 0
	aspectSum := 0.0

	for _, aspect := range aspects {
		switch strings.ToLower(aspect) {
		case "thoroughness":
			metrics.Thoroughness = analyzeThoroughness(comment) // Can still use comment-based thoroughness
			aspectSum += metrics.Thoroughness
			aspectCount++
		case "clarity":
			metrics.Clarity = analyzeClarity(comment) // Can still use comment-based clarity
			aspectSum += metrics.Clarity
			aspectCount++
		case "actionability":
			metrics.Actionability = analyzeActionability(comment) // Can still use comment-based actionability
			aspectSum += metrics.Actionability
			aspectCount++
		}
	}

	if aspectCount > 0 {
		metrics.OverallQuality = aspectSum / float64(aspectCount)
	}

	// Generate targeted recommendations
	for _, ref := range refs {
		// filePath := fmt.Sprintf("%s/%s", repoDir, ref.Filename) // Construct full file path
		filePath := filepath.Join(repoDir, ref.Filename) // Use filepath.Join
        log.Printf("Generating recommendations for file: %s", filePath) // Log file path
		recommendations := generateTargetedRecommendations(filePath, ref, aspects, repoDir)
		metrics.Recommendations = append(metrics.Recommendations, recommendations...)
	}

	return metrics
}

func analyzeThoroughness(comment string) float64 {
	if comment == "" {
        return 50 // Default score for empty comment
    }

	score := 0.0
	maxScore := 10.0

	codeRefs := regexp.MustCompile(`(?:line|lines)\s+\d+(?:\s*-\s*\d+)?|function\s+[a-zA-Z0-9_]+|class\s+[a-zA-Z0-9_]+|method\s+[a-zA-Z0-9_]+|file\s+[a-zA-Z0-9_./]+`)
	codeRefMatches := codeRefs.FindAllString(comment, -1)
	codeRefScore := math.Min(float64(len(codeRefMatches))*0.8, 3.0)
	score += codeRefScore

	technicalTerms := map[string]float64{
		"performance":     0.5,
		"security":        0.5,
		"scalability":     0.5,
		"maintainability": 0.5,
		"testing":         0.4,
		"edge case":       0.4,
		"complexity":      0.4,
		"algorithm":       0.4,
		"pattern":         0.3,
		"readability":     0.3,
		"efficiency":      0.4,
		"memory":          0.4,
		"time complexity": 0.5,
		"space complexity": 0.5,
	}

	technicalScore := 0.0
	for term, value := range technicalTerms {
		if strings.Contains(strings.ToLower(comment), term) {
			technicalScore += value
		}
	}
	score += math.Min(technicalScore, 3.0)

	words := strings.Fields(comment)
	lengthScore := math.Min(float64(len(words))/70.0*2.0, 2.0)
	score += lengthScore

	bulletPoints := regexp.MustCompile(`(?m)^[\s]*[•\-\*]\s`).FindAllString(comment, -1)
	numberedPoints := regexp.MustCompile(`(?m)^[\s]*\d+[\.)]\s`).FindAllString(comment, -1)
	pointsScore := math.Min(float64(len(bulletPoints)+len(numberedPoints))*0.5, 2.0)
	score += pointsScore

	log.Printf("Thoroughness Score: %f (Comment: %s)", score, comment)

	return (score / maxScore) * 100
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

    // response += fmt.Sprintf("\n### Overall Quality: %.1f%%\n", metrics.OverallQuality)

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

// Function to track and analyze historical trends
func trackAnalysisHistory(channelID string, metrics models.CodeReviewMetrics, commentLength int) {
	history := models.AnalysisHistory{
		Date:            time.Now(),
		OverallQuality: metrics.OverallQuality,
		CommentLength:   commentLength,
	}

	if _, exists := analysisHistories[channelID]; !exists {
		analysisHistories[channelID] = []models.AnalysisHistory{}
	}

	analysisHistories[channelID] = append(analysisHistories[channelID], history)

	/* if len(analysisHistories[channelID]) > 100 {
		analysisHistories[channelID] = analysisHistories[channelID][1:]
	} */

	// Keep only the last 10 entries (for example)
	if len(analysisHistories[channelID]) > 10 {
		analysisHistories[channelID] = analysisHistories[channelID][len(analysisHistories[channelID])-10:]
	}
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