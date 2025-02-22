package analyze

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
)

// GoAnalyzer implements language-specific analysis for Go code
type GoAnalyzer struct {
	fset *token.FileSet
}

// NewGoAnalyzer creates a new instance of GoAnalyzer
func NewGoAnalyzer() *GoAnalyzer {
	return &GoAnalyzer{
		fset: token.NewFileSet(),
	}
}

// Analyze performs static code analysis on Go code
func (a *GoAnalyzer) Analyze(filepath, content string) ([]string, error) {
	// Handle content input by creating a temporary file if needed
	if content != "" {
		tempFile, err := os.CreateTemp("", "*.go")
		if err != nil {
			return nil, fmt.Errorf("failed to create temp file: %w", err)
		}
		defer os.Remove(tempFile.Name())
		if _, err := tempFile.Write([]byte(content)); err != nil {
			return nil, fmt.Errorf("failed to write to temp file: %w", err)
		}
		filepath = tempFile.Name()
		tempFile.Close()
	}

	// Parse the Go code
	node, err := parser.ParseFile(a.fset, filepath, nil, parser.ParseComments)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Go code: %w", err)
	}

	var recommendations []string

	// Check for package documentation
	if node.Doc == nil || len(node.Doc.List) == 0 {
		recommendations = append(recommendations, 
			fmt.Sprintf("%s:1: Package lacks documentation comment", filepath))
	}

	// Check imports
	for _, imp := range node.Imports {
		if imp.Name != nil && imp.Name.Name == "_" {
			pos := a.fset.Position(imp.Pos())
			recommendations = append(recommendations, 
				fmt.Sprintf("%s:%d: Blank import found - ensure it's necessary", filepath, pos.Line))
		}
	}

	// Process function declarations
	a.analyzeFunctions(node, filepath, &recommendations)

	// Process error handling in all functions
	a.analyzeErrorHandling(node, filepath, &recommendations)

	// Check for context usage
	if a.hasContextPackage(node) && !a.hasContextParameter(node) {
		recommendations = append(recommendations,
			fmt.Sprintf("%s:1: Using context package but not passing context through functions", filepath))
	}

	return recommendations, nil
}

// analyzeFunctions checks for issues in function declarations
func (a *GoAnalyzer) analyzeFunctions(node *ast.File, filepath string, recommendations *[]string) {
	ast.Inspect(node, func(n ast.Node) bool {
		// Check for long functions
		if fn, ok := n.(*ast.FuncDecl); ok {
			// Check function length
			if fn.Body != nil {
				var stmtCount int
				ast.Inspect(fn.Body, func(stmt ast.Node) bool {
					if _, isStmt := stmt.(ast.Stmt); isStmt && stmt != fn.Body {
						stmtCount++
					}
					return true
				})
				
				if stmtCount > 50 { // Threshold for function length
					pos := a.fset.Position(fn.Pos())
					*recommendations = append(*recommendations, 
						fmt.Sprintf("%s:%d: Function '%s' is too long (%d statements, consider refactoring)", 
							filepath, pos.Line, fn.Name.Name, stmtCount))
				}
			}

			// Check for exported functions without documentation
			if fn.Name.IsExported() && (fn.Doc == nil || len(fn.Doc.List) == 0) {
				pos := a.fset.Position(fn.Pos())
				*recommendations = append(*recommendations, 
					fmt.Sprintf("%s:%d: Exported function '%s' lacks documentation comment", 
						filepath, pos.Line, fn.Name.Name))
			}

			// Check for naked returns in functions with named return values
			if fn.Type.Results != nil && len(fn.Type.Results.List) > 0 {
				hasNamedReturns := false
				for _, field := range fn.Type.Results.List {
					if len(field.Names) > 0 {
						hasNamedReturns = true
						break
					}
				}

				if hasNamedReturns && fn.Body != nil {
					ast.Inspect(fn.Body, func(stmt ast.Node) bool {
						if ret, ok := stmt.(*ast.ReturnStmt); ok && len(ret.Results) == 0 {
							pos := a.fset.Position(ret.Pos())
							*recommendations = append(*recommendations, 
								fmt.Sprintf("%s:%d: Naked return in function '%s' reduces code readability", 
									filepath, pos.Line, fn.Name.Name))
						}
						return true
					})
				}
			}
		}
		return true
	})
}

// analyzeErrorHandling checks for proper error handling
func (a *GoAnalyzer) analyzeErrorHandling(node *ast.File, filepath string, recommendations *[]string) {
	errorChecks := make(map[int]bool)
	errorReturns := make(map[int]bool)
	
	ast.Inspect(node, func(n ast.Node) bool {
		// Check for if err != nil blocks
		if ifStmt, ok := n.(*ast.IfStmt); ok {
			if binExpr, ok := ifStmt.Cond.(*ast.BinaryExpr); ok {
				if binExpr.Op == token.NEQ && isErrorVar(binExpr.X) && isNilLiteral(binExpr.Y) {
					pos := a.fset.Position(ifStmt.Pos())
					errorChecks[pos.Line] = true
					
					// Check if this is a combined assignment and check
					if assignInit, ok := ifStmt.Init.(*ast.AssignStmt); ok {
						if len(assignInit.Rhs) == 1 {
							pos := a.fset.Position(assignInit.Pos())
							*recommendations = append(*recommendations, 
								fmt.Sprintf("%s:%d: Consider separating error assignment and checking for better readability", 
									filepath, pos.Line))
						}
					}
					
					// Check the body of the if statement for proper error handling
					hasErrorReturn := false
					ast.Inspect(ifStmt.Body, func(stmt ast.Node) bool {
						if ret, ok := stmt.(*ast.ReturnStmt); ok {
							for _, result := range ret.Results {
								if isErrorVar(result) {
									hasErrorReturn = true
									errorReturns[pos.Line] = true
									return false
								}
							}
						}
						return true
					})
					
					if !hasErrorReturn {
						*recommendations = append(*recommendations, 
							fmt.Sprintf("%s:%d: Error check doesn't properly return or handle the error", 
								filepath, pos.Line))
					}
				}
			}
		}
		return true
	})
	
	// Verify overall error handling
	if len(errorChecks) > 0 && len(errorReturns) < len(errorChecks)/2 {
		*recommendations = append(*recommendations, 
			fmt.Sprintf("%s:1: Many error checks don't properly return or handle the error", filepath))
	}
}

// isErrorVar checks if an expression is an error variable
func isErrorVar(expr ast.Expr) bool {
	if ident, ok := expr.(*ast.Ident); ok {
		return ident.Name == "err" || strings.HasSuffix(ident.Name, "Err") || strings.HasSuffix(ident.Name, "Error")
	}
	return false
}

// isNilLiteral checks if an expression is a nil literal
func isNilLiteral(expr ast.Expr) bool {
	if ident, ok := expr.(*ast.Ident); ok {
		return ident.Name == "nil"
	}
	return false
}

// hasContextPackage checks if the code imports the context package
func (a *GoAnalyzer) hasContextPackage(node *ast.File) bool {
	for _, imp := range node.Imports {
		if imp.Path != nil {
			pathValue := strings.Trim(imp.Path.Value, "\"")
			if pathValue == "context" {
				return true
			}
		}
	}
	return false
}

// hasContextParameter checks if any function has a context parameter
func (a *GoAnalyzer) hasContextParameter(node *ast.File) bool {
	hasCtx := false
	ast.Inspect(node, func(n ast.Node) bool {
		if fn, ok := n.(*ast.FuncDecl); ok && fn.Type.Params != nil && len(fn.Type.Params.List) > 0 {
			for _, param := range fn.Type.Params.List {
				if sel, ok := param.Type.(*ast.SelectorExpr); ok {
					if x, ok := sel.X.(*ast.Ident); ok && x.Name == "context" && sel.Sel.Name == "Context" {
						hasCtx = true
						return false
					}
				}
			}
		}
		return !hasCtx
	})
	return hasCtx
}

// AnalyzeGoCode is a convenience function that creates and uses a GoAnalyzer
func AnalyzeGoCode(filepath, content string) ([]string, error) {
	analyzer := NewGoAnalyzer()
	return analyzer.Analyze(filepath, content)
}