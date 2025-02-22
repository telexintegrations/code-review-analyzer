# Code Review Analyzer

A specialized tool for analyzing and enhancing code review comments with contextual information from repository files. This service helps improve code review quality by automatically providing relevant code context and analysis for PHP, Java, Python, and Go codebases.

## Features

- **Multiple Code Source Support**
  - GitHub repository integration
  - Direct code snippet analysis
  - Language support for:
    - PHP
    - Java
    - Python
    - Go

- **Smart Context Enhancement**
  - Automatic file reference detection (.php, .java, .py, .go files)
  - Line number parsing and validation
  - Surrounding code context inclusion
  - Language-specific code block formatting

- **Robust Error Handling**
  - Invalid repository URL detection
  - Missing file handling
  - Rate limiting protection
  - Comprehensive error messaging

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/code-review-analyzer.git
cd code-review-analyzer
```

2. Install dependencies:
```bash
go mod download
```

3. Build the project:
```bash
go build
```

## Configuration

The service can be configured using environment variables:

```env
PORT=8080                          # Server port (default: 8080)
GITHUB_TOKEN=your_token_here       # GitHub API token for repository access
LOG_LEVEL=info                     # Logging level (debug, info, warn, error)
RATE_LIMIT=100                     # Requests per minute limit
```

## Usage

### API Endpoints

#### POST /analyze
Analyzes code review comments and enhances them with context.

**Request Body:**
```json
{
  "channel_id": "your-channel-id",
  "settings": [
    {
      "label": "code_source",
      "type": "dropdown",
      "default": "github",
      "required": true,
      "options": ["direct", "github", "gitlab", "bitbucket"]
    },
    {
      "label": "repository_url",
      "type": "text",
      "default": "https://github.com/organization/repo",
      "required": false
    }
  ]
}
```

**Response:**
```json
{
  "message": "Code Review Quality Analysis completed successfully",
  "channel_id": "your-channel-id",
  "enhanced_comment": "Original comment with added code context...",
  "code_context": "relevant_method_name",
  "analysis_timestamp": "2025-02-22T10:30:00Z"
}
```

### Supported File Types

1. **PHP Files (.php)**
   - Class and method analysis
   - Function context extraction
   - PHP-specific syntax highlighting

2. **Java Files (.java)**
   - Class and method detection
   - Line number validation
   - Java syntax context

3. **Python Files (.py)**
   - Function and class analysis
   - Indentation-aware context
   - Python syntax highlighting

4. **Go Files (.go)**
   - Package and function analysis
   - Go-specific syntax support
   - Method context extraction

### Code Source Types

1. **GitHub (`github`)**
   - Requires repository URL
   - Supports file path and line number references
   - Automatically fetches file content

2. **Direct (`direct`)**
   - Accepts inline code snippets
   - Supports markdown code blocks
   - No repository integration needed

## Testing

Run the test suite:

```bash
go test ./... -v
```

Run integration tests:

```bash
go test -tags=integration
```

### Test Coverage

Generate test coverage report:

```bash
go test ./... -coverprofile=coverage.out
go tool cover -html=coverage.out
```

## Error Handling

The service returns appropriate HTTP status codes:

- `200 OK`: Successful analysis
- `400 Bad Request`: Invalid input (URL, missing required fields)
- `401 Unauthorized`: Invalid GitHub token
- `404 Not Found`: Repository or file not found
- `429 Too Many Requests`: Rate limit exceeded
- `500 Internal Server Error`: Server-side issues

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Guidelines

- Write tests for new features
- Update documentation as needed
- Follow Go best practices and coding standards
- Use meaningful commit messages

## Future Enhancements

- Support for additional programming languages
  - JavaScript/TypeScript
  - Ruby
  - C#
  - Rust
- Support for additional code hosting platforms (GitLab, Bitbucket)
- Machine learning-based code review suggestions
- Code quality metrics integration
- Custom rules engine for analysis
- Real-time websocket notifications

## Known Limitations

- Currently only supports PHP, Java, Python, and Go files

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

For support, please create an issue in the GitHub repository or contact the maintainers directly.

## Acknowledgments

- Thanks to all contributors
- Built with Go and modern software development practices
- Inspired by the need for better code review tools