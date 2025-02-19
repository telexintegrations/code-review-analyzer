package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
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

// Structures for Telex integration
type TelexMessage struct {
	ChannelID string          `json:"channel_id"`
	Message   string          `json:"message"`
	Settings  []TelexSettings `json:"settings"`
}

type TelexSettings struct {
	Label       string   `json:"label"`
	Type        string   `json:"type"`
	Description string   `json:"description"`
	Default     string   `json:"default"`
	Value       string   `json:"value,omitempty"` // Added Value field for incoming data
	Required    bool     `json:"required"`
	Options     []string `json:"options,omitempty"`
}

// RepoContent stores repository file content information
type RepoContent struct {
	Content string `json:"content"`
	Name    string `json:"name"`
	Path    string `json:"path"`
	Type    string `json:"type"`
	URL     string `json:"url"`
}

// RepoCodeReference represents a code reference from a review comment
type RepoCodeReference struct {
	Filename    string
	LineStart   int
	LineEnd     int
	Description string
}

// RepositoryService handles code retrieval from different repository sources
type RepositoryService struct {
	httpClient *http.Client
}

// CodeReviewMetrics stores analysis results
type CodeReviewMetrics struct {
	Thoroughness    float64
	Clarity         float64
	Actionability   float64
	OverallQuality  float64
	Recommendations []string
}

// AnalysisHistory tracks review quality over time
type AnalysisHistory struct {
	Date           time.Time
	OverallQuality float64
	CommentLength  int
}

// Global variable to store history (in production, use database)
var analysisHistories = make(map[string][]AnalysisHistory)

// NewRepositoryService creates a new repository service
func NewRepositoryService() *RepositoryService {
	return &RepositoryService{
		httpClient: &http.Client{},
	}
}

// ExtractRepoInfo parses a repository URL to extract owner, repo name, etc.
func ExtractRepoInfo(repoURL string) (provider, owner, repo string, err error) {
	if repoURL == "" {
		return "", "", "", fmt.Errorf("empty repository URL")
	}

	parsedURL, err := url.Parse(repoURL)
	if err != nil {
		return "", "", "", err
	}

	// Extract host (provider)
	switch {
	case strings.Contains(parsedURL.Host, "github.com"):
		provider = "github"
	case strings.Contains(parsedURL.Host, "gitlab.com"):
		provider = "gitlab"
	case strings.Contains(parsedURL.Host, "bitbucket.org"):
		provider = "bitbucket"
	default:
		return "", "", "", fmt.Errorf("unsupported repository provider: %s", parsedURL.Host)
	}

	// Extract owner and repo from path
	parts := strings.Split(strings.TrimPrefix(parsedURL.Path, "/"), "/")
	if len(parts) < 2 {
		return "", "", "", fmt.Errorf("invalid repository URL format")
	}

	owner = parts[0]
	repo = parts[1]

	return provider, owner, repo, nil
}

// GetFileContent retrieves file content from a public repository
func (rs *RepositoryService) GetFileContent(provider, owner, repo, filepath string) (string, error) {
	var apiURL string
	var headers map[string]string

	switch provider {
	case "github":
		apiURL = fmt.Sprintf("https://api.github.com/repos/%s/%s/contents/%s", owner, repo, filepath)
		headers = map[string]string{
			"Accept": "application/vnd.github.v3+json",
		}
	case "gitlab":
		// URL-encode the filepath for GitLab API
		encodedPath := url.PathEscape(filepath)
		apiURL = fmt.Sprintf("https://gitlab.com/api/v4/projects/%s%%2F%s/repository/files/%s/raw?ref=main", 
			owner, repo, encodedPath)
	case "bitbucket":
		apiURL = fmt.Sprintf("https://api.bitbucket.org/2.0/repositories/%s/%s/src/master/%s", 
			owner, repo, filepath)
	default:
		return "", fmt.Errorf("unsupported repository provider: %s", provider)
	}

	// Create request
	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return "", err
	}

	// Add headers
	for key, value := range headers {
		req.Header.Add(key, value)
	}

	// Execute request
	resp, err := rs.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("failed to get file content: %s - %s", resp.Status, string(body))
	}

	// Handle provider-specific response format
	switch provider {
	case "github":
		var repoContent RepoContent
		if err := json.NewDecoder(resp.Body).Decode(&repoContent); err != nil {
			return "", err
		}
		// GitHub returns base64-encoded content
		content, err := decodeBase64(repoContent.Content)
		if err != nil {
			return "", err
		}
		return content, nil
	default:
		// GitLab and Bitbucket return raw content
		content, err := io.ReadAll(resp.Body)
		if err != nil {
			return "", err
		}
		return string(content), nil
	}
}

// decodeBase64 decodes base64 content
func decodeBase64(encodedContent string) (string, error) {
	// GitHub sometimes includes newlines in base64 content
	cleanContent := strings.ReplaceAll(encodedContent, "\n", "")
	decoded, err := base64Decode(cleanContent)
	if err != nil {
		return "", err
	}
	return string(decoded), nil
}

// ExtractCodeReferences parses a code review comment to find file references
func ExtractCodeReferences(comment string) []RepoCodeReference {
	var references []RepoCodeReference

	// Pattern for file references with line numbers
	// Example: "In UserAuthentication.java, lines 45-52,"
	fileLinePattern := regexp.MustCompile(`In\s+([a-zA-Z0-9_./]+)(?:\.(?:java|py|js|go|rb|cs|php|ts|swift|kt|c|cpp|h|hpp))?(?:\s*,\s*lines?\s+(\d+)(?:\s*-\s*(\d+))?)?`)
	
	// Find all matches
	matches := fileLinePattern.FindAllStringSubmatch(comment, -1)
	
	for _, match := range matches {
		if len(match) >= 2 {
			ref := RepoCodeReference{
				Filename: match[1],
			}
			
			// Check if we have line numbers
			if len(match) >= 3 && match[2] != "" {
				// Parse line start
				fmt.Sscanf(match[2], "%d", &ref.LineStart)
				
				// Parse line end if present
				if len(match) >= 4 && match[3] != "" {
					fmt.Sscanf(match[3], "%d", &ref.LineEnd)
				} else {
					// If only one line number is provided
					ref.LineEnd = ref.LineStart
				}
			}
			
			// Extract description (text following the file reference until next sentence or paragraph)
			descStart := strings.Index(comment, match[0]) + len(match[0])
			descEnd := len(comment)
			
			// Find end of this description (next period, next paragraph, etc.)
			periodIndex := strings.Index(comment[descStart:], ".")
			if periodIndex != -1 {
				descEnd = descStart + periodIndex + 1
			}
			
			paraIndex := strings.Index(comment[descStart:], "\n\n")
			if paraIndex != -1 && descStart + paraIndex < descEnd {
				descEnd = descStart + paraIndex
			}
			
			if descStart < descEnd {
				ref.Description = strings.TrimSpace(comment[descStart:descEnd])
			}
			
			references = append(references, ref)
		}
	}
	
	return references
}

// EnhanceCodeReviewWithContext adds relevant file content from the repository
func (rs *RepositoryService) EnhanceCodeReviewWithContext(comment string, provider, owner, repo string) (string, error) {
	if comment == "" || provider == "" || owner == "" || repo == "" {
		return comment, nil // No enhancement possible
	}
	
	// Extract code references from the comment
	references := ExtractCodeReferences(comment)
	if len(references) == 0 {
		return comment, nil // No enhancement needed
	}
	
	enhancedComment := comment
	
	// Enhance each reference with actual code
	for _, ref := range references {
		// Skip references without a filename
		if ref.Filename == "" {
			continue
		}
		
		// Get file content
		content, err := rs.GetFileContent(provider, owner, repo, ref.Filename)
		if err != nil {
			log.Printf("Warning: couldn't get content for %s: %v", ref.Filename, err)
			continue
		}
		
		// Extract relevant lines if line numbers are specified
		var relevantCode string
		if ref.LineStart > 0 {
			lines := strings.Split(content, "\n")
			startIdx := ref.LineStart - 1
			endIdx := ref.LineEnd - 1
			
			if startIdx < 0 {
				startIdx = 0
			}
			if endIdx >= len(lines) {
				endIdx = len(lines) - 1
			}
			if endIdx < startIdx {
				endIdx = startIdx
			}
			
			// Extract specified lines
			relevantLines := lines[startIdx:endIdx+1]
			relevantCode = strings.Join(relevantLines, "\n")
		} else {
			// If no specific lines, just take the first few lines
			lines := strings.Split(content, "\n")
			maxPreviewLines := 10
			if len(lines) > maxPreviewLines {
				relevantCode = strings.Join(lines[:maxPreviewLines], "\n") + "\n// ... (file continues)"
			} else {
				relevantCode = content
			}
		}
		
		// Determine language for syntax highlighting
		language := ""
		if dotIndex := strings.LastIndex(ref.Filename, "."); dotIndex != -1 {
			ext := ref.Filename[dotIndex+1:]
			switch ext {
			case "java":
				language = "java"
			case "py":
				language = "python"
			case "js":
				language = "javascript"
			case "go":
				language = "go"
			case "rb":
				language = "ruby"
			default:
				language = ext
			}
		}
		
		// Create code block with relevant code
		codeBlock := fmt.Sprintf("\n\n**Context for %s**:\n```%s\n%s\n```\n", 
			ref.Filename, language, relevantCode)
		
		// Add to comment in an appropriate position
		// Find where this reference is mentioned
		refPos := strings.Index(enhancedComment, ref.Filename)
		if refPos != -1 {
			// Find end of the paragraph
			paraEnd := strings.Index(enhancedComment[refPos:], "\n\n")
			insertPos := 0
			if paraEnd != -1 {
				insertPos = refPos + paraEnd + 2
			} else {
				insertPos = len(enhancedComment)
			}
			
			// Insert code block
			enhancedComment = enhancedComment[:insertPos] + codeBlock + enhancedComment[insertPos:]
		} else {
			// Append at the end if reference position not found
			enhancedComment += codeBlock
		}
	}
	
	return enhancedComment, nil
}

// Add this function to your main.go to extend the handleCodeReviewAnalysis function
func handleRepositoryIntegration(telexMsg *TelexMessage) error {
	// Get repository settings
	var repoSource, repoURL string
	
	for _, setting := range telexMsg.Settings {
		value := setting.Value
		if value == "" {
			value = setting.Default
		}
		
		switch setting.Label {
		case "code_source":
			repoSource = value
		case "repository_url":
			repoURL = value
		}
	}
	
	// Only process if we're using a repository source and have a URL
	if repoSource != "direct" && repoURL != "" {
		provider, owner, repo, err := ExtractRepoInfo(repoURL)
		if err != nil {
			return fmt.Errorf("failed to parse repository URL: %v", err)
		}
		
		// Create repository service
		repoService := NewRepositoryService()
		
		// Enhance the code review with repository context
		enhancedMessage, err := repoService.EnhanceCodeReviewWithContext(
			telexMsg.Message, provider, owner, repo)
		if err != nil {
			return err
		}
		
		// Update the message with enhanced content
		telexMsg.Message = enhancedMessage
	}
	
	return nil
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

// Update your handleCodeReviewAnalysis function to include repository integration
func handleCodeReviewAnalysisWithRepo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	var telexMsg TelexMessage
	if err := json.NewDecoder(r.Body).Decode(&telexMsg); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	
	// Handle repository integration
	if err := handleRepositoryIntegration(&telexMsg); err != nil {
		log.Printf("Repository integration warning: %v", err)
		// Continue processing even if repo integration fails
	}
	
	// Extract settings
	minQualityThreshold := 70.0
	analysisAspects := []string{"Thoroughness", "Clarity", "Actionability"}
	includeRecommendations := true
	
	// Get the value from settings
	for _, setting := range telexMsg.Settings {
		value := setting.Value
		if value == "" {
			value = setting.Default
		}
		
		switch setting.Label {
		case "minimum_quality_threshold":
			if val, err := strconv.ParseFloat(value, 64); err == nil {
				minQualityThreshold = val
			}
		case "analysis_aspects":
			if value != "" {
				analysisAspects = strings.Split(value, ",")
			}
		case "include_recommendations":
			if strings.ToLower(value) == "false" {
				includeRecommendations = false
			}
		}
	}
	
	// Analyze the code review comment
	metrics := analyzeCodeReview(telexMsg.Message, analysisAspects)
	
	// Track analysis history for trends
	trackAnalysisHistory(telexMsg.ChannelID, metrics, len(telexMsg.Message))
	
	// Get historical trends
	trends := getHistoricalTrends(telexMsg.ChannelID)
	
	// Generate enhanced response with analysis, recommendations, and trends
	response := generateEnhancedResponse(metrics, minQualityThreshold, includeRecommendations, trends)
	
	message := map[string]string{
		"event_name": "message_formatted",
		"message":    response,
		"status":     getQualityStatus(metrics.OverallQuality, minQualityThreshold),
		"username":   "Code Review Analyzer",
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(message)
}

// Helper function for GitHub API base64 decoding (add to your imports: "encoding/base64")
func base64Decode(input string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(input)
}

// Helper function to determine quality status
func getQualityStatus(quality, threshold float64) string {
	if quality >= threshold {
		return "success"
	} else if quality >= threshold*0.7 {
		return "warning"
	}
	return "error"
}

// Enhanced analyzeCodeReview function
func analyzeCodeReview(comment string, aspects []string) CodeReviewMetrics {
	metrics := CodeReviewMetrics{
		Recommendations: []string{},
	}
	
	// Initialize counters
	aspectCount := 0
	aspectSum := 0.0
	
	// Only analyze requested aspects
	for _, aspect := range aspects {
		switch strings.ToLower(aspect) {
		case "thoroughness":
			metrics.Thoroughness = analyzeThoroughness(comment)
			aspectSum += metrics.Thoroughness
			aspectCount++
		case "clarity":
			metrics.Clarity = analyzeClarity(comment)
			aspectSum += metrics.Clarity
			aspectCount++
		case "actionability":
			metrics.Actionability = analyzeActionability(comment)
			aspectSum += metrics.Actionability
			aspectCount++
		}
	}
	
	// Calculate overall quality based on selected aspects
	if aspectCount > 0 {
		metrics.OverallQuality = aspectSum / float64(aspectCount)
	}
	
	// Generate recommendations
	metrics.Recommendations = generateRecommendations(metrics, aspects)
	
	return metrics
}

func analyzeThoroughness(comment string) float64 {
	score := 0.0
	maxScore := 10.0
	
	// Check for code specific references (improved regex)
	codeRefs := regexp.MustCompile(`(?:line|lines)\s+\d+(?:\s*-\s*\d+)?|function\s+[a-zA-Z0-9_]+|class\s+[a-zA-Z0-9_]+|method\s+[a-zA-Z0-9_]+|file\s+[a-zA-Z0-9_./]+`)
	codeRefMatches := codeRefs.FindAllString(comment, -1)
	codeRefScore := math.Min(float64(len(codeRefMatches))*0.8, 3.0)
	score += codeRefScore
	
	// Check for technical depth
	technicalTerms := map[string]float64{
		"performance":      0.5, "security":            0.5, "scalability": 0.5, 
		"maintainability":  0.5, "testing":             0.4, "edge case":   0.4,
		"complexity":       0.4, "algorithm":           0.4, "pattern":     0.3,
		"readability":      0.3, "efficiency":          0.4, "memory":      0.4,
		"time complexity":  0.5, "space complexity":    0.5,
	}
	
	technicalScore := 0.0
	for term, value := range technicalTerms {
		if strings.Contains(strings.ToLower(comment), term) {
			technicalScore += value
		}
	}
	score += math.Min(technicalScore, 3.0)
	
	// Check for length and detail
	words := strings.Fields(comment)
	lengthScore := math.Min(float64(len(words))/70.0 * 2.0, 2.0)
	score += lengthScore
	
	// Check for multiple points of feedback
	bulletPoints := regexp.MustCompile(`(?m)^[\s]*[•\-\*]\s`).FindAllString(comment, -1)
	numberedPoints := regexp.MustCompile(`(?m)^[\s]*\d+[\.)]\s`).FindAllString(comment, -1)
	pointsScore := math.Min(float64(len(bulletPoints)+len(numberedPoints))*0.5, 2.0)
	score += pointsScore
	
	return (score / maxScore) * 100
}

func analyzeClarity(comment string) float64 {
	score := 0.0
	maxScore := 10.0
	
	// Check for structure (paragraphs, bullet points)
	paragraphs := strings.Count(comment, "\n\n") + 1
	structureScore := math.Min(float64(paragraphs)*0.7, 2.0)
	
	bulletPoints := regexp.MustCompile(`(?m)^[\s]*[•\-\*]\s`).FindAllString(comment, -1)
	numberedPoints := regexp.MustCompile(`(?m)^[\s]*\d+[\.)]\s`).FindAllString(comment, -1)
	listScore := math.Min(float64(len(bulletPoints)+len(numberedPoints))*0.5, 2.0)
	
	score += math.Max(structureScore, listScore)
	
	// Check for explanation presence
	explanationTerms := regexp.MustCompile(`because|since|as|therefore|consequently|this means|in order to|which leads to|resulting in`)
	explanationMatches := explanationTerms.FindAllString(strings.ToLower(comment), -1)
	explanationScore := math.Min(float64(len(explanationMatches))*0.8, 2.5)
	score += explanationScore
	
	// Check for code examples or suggestions
	codeExamples := regexp.MustCompile("```[^`]*```|`[^`]+`").FindAllString(comment, -1)
	codeScore := math.Min(float64(len(codeExamples))*1.0, 2.5)
	score += codeScore
	
	// Check for comparative language (before/after, current/suggested)
	comparativeTerms := regexp.MustCompile(`instead of|rather than|compared to|current|suggested|alternative|better approach|improvement`)
	comparativeMatches := comparativeTerms.FindAllString(strings.ToLower(comment), -1)
	comparativeScore := math.Min(float64(len(comparativeMatches))*0.5, 1.5)
	score += comparativeScore
	
	// Check for reasonable sentence length (not too long or complex)
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
	
	// Check for specific suggestions using improved patterns
	suggestionTerms := regexp.MustCompile(`(?i)suggest|consider|recommend|try|could|should|need to|must|important to|better to|preferable|advised`)
	suggestionMatches := suggestionTerms.FindAllString(comment, -1)
	suggestionScore := math.Min(float64(len(suggestionMatches))*0.6, 2.5)
	score += suggestionScore
	
	// Check for code examples (both inline and block)
	inlineCode := regexp.MustCompile("`[^`]+`").FindAllString(comment, -1)
	blockCode := regexp.MustCompile("```[^`]*```").FindAllString(comment, -1)
	codeScore := math.Min(float64(len(inlineCode))*0.7 + float64(len(blockCode))*1.5, 3.0)
	score += codeScore
	
	// Check for clear action items
	actionItems := regexp.MustCompile(`(?i)(?:^|\n)\s*(?:\d+[.)\s]+|\*\s+|[-•]\s+)(?:.*?(?:move|add|remove|refactor|rename|extract|inline|implement|fix|update|change|simplify|optimize|delete|rewrite|convert|prevent|handle|include|exclude|ensure|verify|check|confirm|validate)[^.!?\n]*)`).FindAllString(comment, -1)
	todoItems := regexp.MustCompile(`(?i)TODO:|FIXME:|BUG:|ISSUE:`).FindAllString(comment, -1)
	actionScore := math.Min(float64(len(actionItems))*0.8 + float64(len(todoItems))*1.0, 2.5)
	score += actionScore
	
	// Check for specific implementation details
	implementationDetails := regexp.MustCompile(`(?i)implement using|change to|replace with|switch to|move from|convert to|transform into|use the|apply the|following syntax|pattern|approach`).FindAllString(comment, -1)
	implScore := math.Min(float64(len(implementationDetails))*0.6, 2.0)
	score += implScore
	
	return (score / maxScore) * 100
}

func generateRecommendations(metrics CodeReviewMetrics, aspects []string) []string {
	var recommendations []string
	
	aspectMap := make(map[string]bool)
	for _, aspect := range aspects {
		aspectMap[strings.ToLower(aspect)] = true
	}
	
	if aspectMap["thoroughness"] && metrics.Thoroughness < 70 {
		if metrics.Thoroughness < 50 {
			recommendations = append(recommendations, "🔍 Add specific code references (line numbers, function names) and discuss technical implications in detail")
		} else {
			recommendations = append(recommendations, "🔍 Improve thoroughness by adding more specific code location references")
		}
	}
	
	if aspectMap["clarity"] && metrics.Clarity < 70 {
		if metrics.Clarity < 50 {
			recommendations = append(recommendations, "📝 Structure your feedback with paragraphs, bullet points, and include reasoning behind suggestions")
		} else {
			recommendations = append(recommendations, "📝 Improve clarity by explaining the 'why' behind your feedback")
		}
	}
	
	if aspectMap["actionability"] && metrics.Actionability < 70 {
		if metrics.Actionability < 50 {
			recommendations = append(recommendations, "✅ Include specific code examples and clear action items that explain what needs to change")
		} else {
			recommendations = append(recommendations, "✅ Improve actionability by providing more concrete code examples")
		}
	}
	
	return recommendations
}

func generateResponse(metrics CodeReviewMetrics, threshold float64, includeRecommendations bool) string {
	// Create quality indicators
	getQualityEmoji := func(score float64) string {
		if score >= 85 {
			return "🟢"
		} else if score >= threshold {
			return "🟡"
		} else {
			return "🔴"
		}
	}
	
	// Format metrics with emojis
	response := "## Code Review Quality Analysis\n\n"
	
	// Only include analyzed metrics
	if metrics.Thoroughness > 0 {
		response += fmt.Sprintf("%s **Thoroughness**: %.1f%%\n", getQualityEmoji(metrics.Thoroughness), metrics.Thoroughness)
	}
	
	if metrics.Clarity > 0 {
		response += fmt.Sprintf("%s **Clarity**: %.1f%%\n", getQualityEmoji(metrics.Clarity), metrics.Clarity)
	}
	
	if metrics.Actionability > 0 {
		response += fmt.Sprintf("%s **Actionability**: %.1f%%\n", getQualityEmoji(metrics.Actionability), metrics.Actionability)
	}
	
	response += fmt.Sprintf("\n### Overall Quality: %.1f%%\n", metrics.OverallQuality)
	
	// Add threshold indicator
	if metrics.OverallQuality >= threshold {
		response += fmt.Sprintf("\n✅ **Meets quality threshold** (%.1f%%)\n", threshold)
	} else {
		response += fmt.Sprintf("\n⚠️ **Below quality threshold** (%.1f%%)\n", threshold)
	}

	// Include recommendations if requested
	if includeRecommendations && len(metrics.Recommendations) > 0 {
		response += "\n### Recommendations for Improvement\n"
		for _, rec := range metrics.Recommendations {
			response += fmt.Sprintf("%s\n", rec)
		}
	}
	
	return response
}

// Function to track and analyze historical trends
func trackAnalysisHistory(channelID string, metrics CodeReviewMetrics, commentLength int) {
	history := AnalysisHistory{
		Date:           time.Now(),
		OverallQuality: metrics.OverallQuality,
		CommentLength:  commentLength,
	}
	
	// If first entry for this channel, initialize slice
	if _, exists := analysisHistories[channelID]; !exists {
		analysisHistories[channelID] = []AnalysisHistory{}
	}
	
	// Add entry to history
	analysisHistories[channelID] = append(analysisHistories[channelID], history)
	
	// Keep only last 100 entries
	if len(analysisHistories[channelID]) > 100 {
		analysisHistories[channelID] = analysisHistories[channelID][1:]
	}
}

// Function to get historical trends
func getHistoricalTrends(channelID string) map[string]float64 {
	history := analysisHistories[channelID]
	if len(history) < 2 {
		return map[string]float64{
			"trend": 0,
			"average": 0,
		}
	}
	
	// Calculate average quality
	totalQuality := 0.0
	for _, entry := range history {
		totalQuality += entry.OverallQuality
	}
	average := totalQuality / float64(len(history))
	
	// Calculate trend (simple linear regression)
	recent := history[len(history)-10:]
	if len(recent) < 2 {
		recent = history
	}
	
	firstQuality := recent[0].OverallQuality
	lastQuality := recent[len(recent)-1].OverallQuality
	trend := lastQuality - firstQuality
	
	return map[string]float64{
		"trend": trend,
		"average": average,
	}
}

// Enhanced response generator with trend information
func generateEnhancedResponse(metrics CodeReviewMetrics, threshold float64, includeRecommendations bool, trends map[string]float64) string {
	// Basic response from previous function
	baseResponse := generateResponse(metrics, threshold, includeRecommendations)
	
	// Add trend information if available
	if trends["average"] > 0 {
		trendEmoji := "➡️"
		if trends["trend"] > 5 {
			trendEmoji = "📈"
		} else if trends["trend"] < -5 {
			trendEmoji = "📉"
		}
		
		trendResponse := fmt.Sprintf("\n### Historical Perspective\n%s Quality trend: ", trendEmoji)
		if math.Abs(trends["trend"]) < 2 {
			trendResponse += "Stable"
		} else if trends["trend"] > 0 {
			trendResponse += fmt.Sprintf("Improving (↑%.1f%%)", trends["trend"])
		} else {
			trendResponse += fmt.Sprintf("Declining (↓%.1f%%)", math.Abs(trends["trend"]))
		}
		
		// Compare to historical average
		comparisonEmoji := "➡️"
		diff := metrics.OverallQuality - trends["average"]
		if diff > 5 {
			comparisonEmoji = "🌟"
		} else if diff < -5 {
			comparisonEmoji = "⚠️"
		}
		
		trendResponse += fmt.Sprintf("\n%s Compared to average: ", comparisonEmoji)
		if math.Abs(diff) < 2 {
			trendResponse += "On par with typical reviews"
		} else if diff > 0 {
			trendResponse += fmt.Sprintf("Above average by %.1f%%", diff)
		} else {
			trendResponse += fmt.Sprintf("Below average by %.1f%%", math.Abs(diff))
		}
		
		// Combine responses
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