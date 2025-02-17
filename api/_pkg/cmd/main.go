package main

import (
    "encoding/json"
    "log"
    "net/http"
    "os"
    "strings"
    p "template-go-vercel/api/_pkg"
)

// Message represents the incoming request structure
type Message struct {
    ChannelID string    `json:"channel_id"`
    Settings  []Setting `json:"settings"`
    Message   string    `json:"message"`
}

// Setting represents a configuration setting
type Setting struct {
    Label       string      `json:"label"`
    Type        string      `json:"type"`
    Description string      `json:"description"`
    Required    bool        `json:"required"`
    Default     interface{} `json:"default"`
}

// TextFormatter handles the text formatting logic
type TextFormatter struct {
    targetWords  []string
    preserveCase bool
    addAsterisk  bool
}

func newTextFormatter() *TextFormatter {
    return &TextFormatter{
        targetWords:  []string{},
        preserveCase: true,
        addAsterisk:  true,
    }
}

func (tf *TextFormatter) formatText(text string) string {
    words := strings.Fields(text)
    result := make([]string, len(words))

    for i, word := range words {
        cleanWord := strings.Trim(word, ".,!?;:")
        punctuation := word[len(cleanWord):]

        for _, target := range tf.targetWords {
            if strings.EqualFold(cleanWord, target) {
                formattedWord := strings.ToUpper(cleanWord)
                if tf.addAsterisk {
                    formattedWord = "**" + formattedWord + "**"
                }
                formattedWord += punctuation
                result[i] = formattedWord
                goto nextWord
            }
        }

        if tf.preserveCase {
            result[i] = word
        } else {
            result[i] = strings.ToLower(word)
        }

    nextWord:
    }

    return strings.Join(result, " ")
}

// handleFormatText processes the text formatting request
func handleFormatText(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }

    var msgReq Message
    if err := json.NewDecoder(r.Body).Decode(&msgReq); err != nil {
        http.Error(w, "Bad request", http.StatusBadRequest)
        return
    }

    formatter := newTextFormatter()

    // Update formatter settings from request
    for _, setting := range msgReq.Settings {
        switch setting.Label {
        case "targetWords":
            if val, ok := setting.Default.(string); ok {
                formatter.targetWords = strings.Split(val, ",")
                for i, word := range formatter.targetWords {
                    formatter.targetWords[i] = strings.TrimSpace(word)
                }
            }
        case "preserveCase":
            if val, ok := setting.Default.(bool); ok {
                formatter.preserveCase = val
            }
        case "addAsterisk":
            if val, ok := setting.Default.(bool); ok {
                formatter.addAsterisk = val
            }
        }
    }

    formattedText := formatter.formatText(msgReq.Message)

    log.Printf("Original: %s", msgReq.Message)
    log.Printf("Formatted: %s", formattedText)

    response := map[string]string{
        "event_name": "text_formatted",
        "message":    formattedText,
        "status":     "success",
        "username":   "text-formatter-bot",
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(response)
}

// handleFormatterJSON serves the JSON configuration
func handleFormatterJSON(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodGet {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }

    filePath := "./formatter.json" // Ensure this file exists at root
    byteValue, err := os.ReadFile(filePath)
    if err != nil {
        http.Error(w, "Failed to read formatter configuration", http.StatusInternalServerError)
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

func main() {
	http.HandleFunc("/format-text", enableCORS(handleFormatText))
	http.HandleFunc("/formatter-json", enableCORS(handleFormatterJSON))
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	log.Printf("Server running on port %s", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}