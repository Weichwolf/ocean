package main

import (
	"go/ast"
	"go/types"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/unitchecker"
	"golang.org/x/tools/go/types/typeutil"
)

var discardedErrors = &analysis.Analyzer{
	Name: "discardederrors",
	Doc:  "check explicitly discarded errors from decoding and persistent writes",
	Run:  checkDiscardedErrors,
}

func main() {
	unitchecker.Main(discardedErrors)
}

func checkDiscardedErrors(pass *analysis.Pass) (any, error) {
	for _, file := range pass.Files {
		ast.Inspect(file, func(node ast.Node) bool {
			switch node := node.(type) {
			case *ast.AssignStmt:
				for i, lhs := range node.Lhs {
					if blank, ok := lhs.(*ast.Ident); ok && blank.Name == "_" {
						checkErrorResult(pass, blank, i, node.Rhs)
					}
				}
			case *ast.ValueSpec:
				for i, name := range node.Names {
					if name.Name == "_" && len(node.Values) > 0 {
						checkErrorResult(pass, name, i, node.Values)
					}
				}
			}
			return true
		})
	}
	return nil, nil
}

func checkErrorResult(pass *analysis.Pass, blank *ast.Ident, index int, values []ast.Expr) {
	expr, result := values[0], index
	if len(values) > 1 {
		expr, result = values[index], 0
	}
	call, ok := ast.Unparen(expr).(*ast.CallExpr)
	if !ok {
		return
	}
	function, ok := typeutil.Callee(pass.TypesInfo, call).(*types.Func)
	if !ok {
		return
	}
	name := function.FullName()
	switch name {
	case "encoding/json.Unmarshal", "(*encoding/json.Decoder).Decode",
		"go.yaml.in/yaml/v3.Unmarshal", "(*go.yaml.in/yaml/v3.Decoder).Decode",
		"os.WriteFile", "os.Rename", "(*os.Root).WriteFile", "(*os.Root).Rename",
		"(*os.File).Write", "(*os.File).WriteAt", "(*os.File).WriteString", "(*os.File).Sync",
		"(go.etcd.io/etcd/client/v3.Txn).Commit":
		results := function.Signature().Results()
		if result < results.Len() && types.Identical(results.At(result).Type(), types.Universe.Lookup("error").Type()) {
			pass.Reportf(blank.Pos(), "check the error returned by %s", name)
		}
	}
}
