package test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
)

// TestRepositoryIntegration shows how the integration works with sample data
func TestRepositoryIntegration() {
	// Sample payload for a GitHub repository
	payload := TelexMessage{
		ChannelID: "channel-123",
		Message: "In UserAuthentication.java, lines 45-52, the token validation logic doesn't handle expired tokens correctly. Consider adding a proper check for token expiration before proceeding with validation.",
		Settings: []TelexSettings{
			{
				Label:       "code_source",
				Type:        "dropdown",
				Description: "Source of code to analyze",
				Default:     "github",
				Value:       "github",
				Required:    true,
				Options:     []string{"direct", "github", "gitlab", "bitbucket"},
			},
			{
				Label:       "repository_url",
				Type:        "text",
				Description: "Repository URL",
				Default:     "",
				Value:       "https://github.com/octocat/Hello-World", // Example public repo
				Required:    false,
			},
			{
				Label:       "minimum_quality_threshold",
				Type:        "number",
				Description: "Minimum acceptable quality score (0-100)",
				Default:     "75",
				Value:       "75",
				Required:    true,
			},
			{
				Label:       "analysis_aspects",
				Type:        "multi-checkbox",
				Description: "Which aspects of the code review to analyze",
				Default:     "Thoroughness,Clarity,Actionability",
				Value:       "Thoroughness,Clarity,Actionability",
				Options:     []string{"Thoroughness", "Clarity", "Actionability"},
				Required:    true,
			},
			{
				Label:       "include_recommendations",
				Type:        "checkbox",
				Description: "Include specific improvement recommendations in the analysis",
				Default:     "true",
				Value:       "true",
				Required:    true,
			},
		},
	}

	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// This would normally go through your handleCodeReviewAnalysisWithRepo
		
		// For test purposes, let's simulate the repository integration
		err := handleRepositoryIntegration(&payload)
		if err != nil {
			fmt.Printf("Repository integration error: %v\n", err)
		}
		
		// Check if the message was enhanced with repository context
		fmt.Println("Original message length:", len(payload.Message))
		fmt.Println("Enhanced message length:", len(payload.Message))
		fmt.Println("Message contains code block:", bytes.Contains([]byte(payload.Message), []byte("```")))
		
		// Simulate analyzing and responding
		metrics := analyzeCodeReview(payload.Message, []string{"Thoroughness", "Clarity", "Actionability"})
		response := generateEnhancedResponse(metrics, 75.0, true, map[string]float64{
			"trend":   2.5,
			"average": 78.3,
		})
		
		// Return response
		message := map[string]string{
			"event_name": "message_formatted",
			"message":    response,
			"status":     getQualityStatus(metrics.OverallQuality, 75.0),
			"username":   "Code Review Analyzer",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(message)
	}))
	defer server.Close()
	
	// Prepare request
	payloadBytes, _ := json.Marshal(payload)
	req, err := http.NewRequest("POST", server.URL, bytes.NewBuffer(payloadBytes))
	if err != nil {
		log.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	
	// Send request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()
	
	// Decode response
	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)
	
	// Print result
	fmt.Println("Status:", resp.Status)
	fmt.Println("Response:", result)
}

// ExampleUsage shows how to use the repository service directly
func ExampleUsage() {
	// Create repository service
	repoService := NewRepositoryService()
	
	// Example: Get file content from a public GitHub repository
	provider, owner, repo := "github", "octocat", "Hello-World"
	filepath := "README.md"
	
	content, err := repoService.GetFileContent(provider, owner, repo, filepath)
	if err != nil {
		fmt.Printf("Error getting file content: %v\n", err)
		return
	}
	
	fmt.Printf("File content (%d bytes):\n%s\n", len(content), content[:100])
	
	// Example: Enhance a code review comment
	comment := "In README.md, the project description is unclear. Consider adding more details about the purpose of the project."
	enhanced, err := repoService.EnhanceCodeReviewWithContext(comment, provider, owner, repo)
	if err != nil {
		fmt.Printf("Error enhancing comment: %v\n", err)
		return
	}
	
	fmt.Printf("Enhanced comment (%d bytes):\n%s\n", len(enhanced), enhanced)
}

// test function that runs examples when executed
func test() {
	fmt.Println("Running repository integration tests...")
	TestRepositoryIntegration()
	fmt.Println("\nRunning repository service examples...")
	ExampleUsage()
}