package models
// Package models contains shared data structures for the code review analyzer

import (
	"time"
)

// TelexMessage represents a message from the Telex system
type TelexMessage struct {
	ChannelID string          `json:"channel_id"`
	Message   string          `json:"message"`
	Settings  []TelexSettings `json:"settings"`
}

// TelexSettings represents settings for Telex integration
type TelexSettings struct {
	Label       string   `json:"label"`
	Type        string   `json:"type"`
	Description string   `json:"description"`
	Default     string   `json:"default"`
	Value       string   `json:"value,omitempty"`
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
	Thoroughness   float64
	Clarity        float64
	Actionability  float64
	Average        float64
	Trend          float64
}