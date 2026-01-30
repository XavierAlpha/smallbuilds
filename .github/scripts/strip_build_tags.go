package main

import (
	"bytes"
	"flag"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
)

type config struct {
	file      string
	exactTags []string
	prefixes  []string
	printInit bool
}

func main() {
	cfg := parseConfig()
	if cfg.file == "" {
		fmt.Fprintln(os.Stderr, "missing --file")
		os.Exit(2)
	}

	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, cfg.file, nil, parser.ParseComments)
	if err != nil {
		fmt.Fprintln(os.Stderr, "parse:", err)
		os.Exit(1)
	}

	exactSet := make(map[string]bool, len(cfg.exactTags))
	for _, t := range cfg.exactTags {
		exactSet[t] = true
	}

	shouldRemove := func(s string) bool {
		if exactSet[s] {
			return true
		}
		for _, p := range cfg.prefixes {
			if strings.HasPrefix(s, p) {
				return true
			}
		}
		return false
	}

	rewriteFile(f, shouldRemove)

	remaining := findRemaining(f, fset, shouldRemove)
	if len(remaining) > 0 {
		fmt.Fprintln(os.Stderr, "tags still present after patch:")
		for _, r := range remaining {
			fmt.Fprintf(os.Stderr, "  %s at %s\n", r.tag, r.pos)
		}
		os.Exit(1)
	}

	if cfg.printInit {
		printInitFunctions(f, fset)
	}

	var buf bytes.Buffer
	if err := format.Node(&buf, fset, f); err != nil {
		fmt.Fprintln(os.Stderr, "format:", err)
		os.Exit(1)
	}
	if err := os.WriteFile(cfg.file, buf.Bytes(), 0644); err != nil {
		fmt.Fprintln(os.Stderr, "write:", err)
		os.Exit(1)
	}
}

func parseConfig() config {
	file := flag.String("file", "", "path to Go source file")
	tags := flag.String("tags", "", "comma-separated exact tags to remove (overrides STRIP_TAGS)")
	prefixes := flag.String("prefixes", "", "comma-separated tag prefixes to remove (overrides STRIP_TAGS_PREFIXES)")
	printInit := flag.Bool("print-init", false, "print all init() functions after patch")
	flag.Parse()

	exactList := parseList(*tags, "STRIP_TAGS", []string{
		"with_wireguard",
		"with_naive_outbound",
		"with_tailscale",
	})
	prefixList := parseList(*prefixes, "STRIP_TAGS_PREFIXES", []string{"ts_"})

	return config{
		file:      *file,
		exactTags: exactList,
		prefixes:  prefixList,
		printInit: *printInit,
	}
}

func parseList(flagValue string, envKey string, defaults []string) []string {
	raw := strings.TrimSpace(flagValue)
	if raw == "" {
		raw = strings.TrimSpace(os.Getenv(envKey))
	}
	var src []string
	if raw == "" {
		src = defaults
	} else {
		src = strings.Split(raw, ",")
	}
	out := make([]string, 0, len(src))
	for _, t := range src {
		t = strings.TrimSpace(t)
		if t != "" {
			out = append(out, t)
		}
	}
	return out
}

func printInitFunctions(f *ast.File, fset *token.FileSet) {
	count := 0
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv != nil || fn.Name == nil || fn.Name.Name != "init" {
			continue
		}
		count++
		fmt.Printf("==== Patched func init() #%d ====\n", count)
		var buf bytes.Buffer
		if err := format.Node(&buf, fset, fn); err != nil {
			fmt.Fprintf(os.Stderr, "format init(): %v\n", err)
			continue
		}
		fmt.Print(buf.String())
		fmt.Print("\n\n")
	}
	if count == 0 {
		fmt.Println("No init() functions found.")
	}
}

func rewriteFile(f *ast.File, shouldRemove func(string) bool) {
	for _, decl := range f.Decls {
		switch d := decl.(type) {
		case *ast.FuncDecl:
			rewriteBlock(d.Body, shouldRemove)
		case *ast.GenDecl:
			for _, spec := range d.Specs {
				rewriteSpec(spec, shouldRemove)
			}
		}
	}
}

func rewriteSpec(spec ast.Spec, shouldRemove func(string) bool) {
	switch s := spec.(type) {
	case *ast.ValueSpec:
		for i, v := range s.Values {
			s.Values[i] = rewriteExpr(v, shouldRemove)
		}
	}
}

func rewriteBlock(b *ast.BlockStmt, shouldRemove func(string) bool) {
	if b == nil {
		return
	}
	out := make([]ast.Stmt, 0, len(b.List))
	for _, stmt := range b.List {
		if s := rewriteStmt(stmt, shouldRemove); s != nil {
			out = append(out, s)
		}
	}
	b.List = out
}

func rewriteStmt(stmt ast.Stmt, shouldRemove func(string) bool) ast.Stmt {
	switch s := stmt.(type) {
	case *ast.AssignStmt:
		for i, v := range s.Lhs {
			s.Lhs[i] = rewriteExpr(v, shouldRemove)
		}
		for i, v := range s.Rhs {
			s.Rhs[i] = rewriteExpr(v, shouldRemove)
		}
		return s
	case *ast.ExprStmt:
		wasAppend := isCallIdentExpr(s.X, "append")
		s.X = rewriteExpr(s.X, shouldRemove)
		if wasAppend {
			if _, ok := s.X.(*ast.CallExpr); !ok {
				return nil
			}
		}
		return s
	case *ast.ReturnStmt:
		for i, v := range s.Results {
			s.Results[i] = rewriteExpr(v, shouldRemove)
		}
		return s
	case *ast.IfStmt:
		if s.Init != nil {
			s.Init = rewriteStmt(s.Init, shouldRemove)
		}
		if s.Cond != nil {
			s.Cond = rewriteExpr(s.Cond, shouldRemove)
		}
		rewriteBlock(s.Body, shouldRemove)
		if s.Else != nil {
			s.Else = rewriteStmt(s.Else, shouldRemove)
		}
		return s
	case *ast.ForStmt:
		if s.Init != nil {
			s.Init = rewriteStmt(s.Init, shouldRemove)
		}
		if s.Cond != nil {
			s.Cond = rewriteExpr(s.Cond, shouldRemove)
		}
		if s.Post != nil {
			s.Post = rewriteStmt(s.Post, shouldRemove)
		}
		rewriteBlock(s.Body, shouldRemove)
		return s
	case *ast.RangeStmt:
		if s.Key != nil {
			s.Key = rewriteExpr(s.Key, shouldRemove)
		}
		if s.Value != nil {
			s.Value = rewriteExpr(s.Value, shouldRemove)
		}
		s.X = rewriteExpr(s.X, shouldRemove)
		rewriteBlock(s.Body, shouldRemove)
		return s
	case *ast.SwitchStmt:
		if s.Init != nil {
			s.Init = rewriteStmt(s.Init, shouldRemove)
		}
		if s.Tag != nil {
			s.Tag = rewriteExpr(s.Tag, shouldRemove)
		}
		rewriteBlock(s.Body, shouldRemove)
		return s
	case *ast.TypeSwitchStmt:
		if s.Init != nil {
			s.Init = rewriteStmt(s.Init, shouldRemove)
		}
		if s.Assign != nil {
			s.Assign = rewriteStmt(s.Assign, shouldRemove)
		}
		rewriteBlock(s.Body, shouldRemove)
		return s
	case *ast.SelectStmt:
		rewriteBlock(s.Body, shouldRemove)
		return s
	case *ast.CaseClause:
		for i, v := range s.List {
			s.List[i] = rewriteExpr(v, shouldRemove)
		}
		out := make([]ast.Stmt, 0, len(s.Body))
		for _, st := range s.Body {
			if rs := rewriteStmt(st, shouldRemove); rs != nil {
				out = append(out, rs)
			}
		}
		s.Body = out
		return s
	case *ast.CommClause:
		if s.Comm != nil {
			s.Comm = rewriteStmt(s.Comm, shouldRemove)
		}
		out := make([]ast.Stmt, 0, len(s.Body))
		for _, st := range s.Body {
			if rs := rewriteStmt(st, shouldRemove); rs != nil {
				out = append(out, rs)
			}
		}
		s.Body = out
		return s
	case *ast.BlockStmt:
		rewriteBlock(s, shouldRemove)
		return s
	case *ast.DeclStmt:
		rewriteDecl(s.Decl, shouldRemove)
		return s
	case *ast.GoStmt:
		if s.Call != nil {
			if call, ok := rewriteExpr(s.Call, shouldRemove).(*ast.CallExpr); ok {
				s.Call = call
			}
		}
		return s
	case *ast.DeferStmt:
		if s.Call != nil {
			if call, ok := rewriteExpr(s.Call, shouldRemove).(*ast.CallExpr); ok {
				s.Call = call
			}
		}
		return s
	default:
		return s
	}
}

func rewriteDecl(decl ast.Decl, shouldRemove func(string) bool) {
	switch d := decl.(type) {
	case *ast.GenDecl:
		for _, spec := range d.Specs {
			rewriteSpec(spec, shouldRemove)
		}
	}
}

func rewriteExpr(e ast.Expr, shouldRemove func(string) bool) ast.Expr {
	switch v := e.(type) {
	case *ast.CallExpr:
		v.Fun = rewriteExpr(v.Fun, shouldRemove)
		for i, arg := range v.Args {
			v.Args[i] = rewriteExpr(arg, shouldRemove)
		}

		if isCallIdentExpr(v.Fun, "append") && len(v.Args) >= 2 {
			kept := []ast.Expr{v.Args[0]}
			for _, a := range v.Args[1:] {
				if isRemoveStringLit(a, shouldRemove) {
					continue
				}
				kept = append(kept, a)
			}
			v.Args = kept
			if len(kept) == 1 {
				return kept[0]
			}
			return v
		}

		if isCallIdentExpr(v.Fun, "filterTags") && len(v.Args) >= 2 {
			kept := []ast.Expr{v.Args[0]}
			for _, a := range v.Args[1:] {
				if isRemoveStringLit(a, shouldRemove) {
					continue
				}
				kept = append(kept, a)
			}
			v.Args = kept
			return v
		}

		return v
	case *ast.CompositeLit:
		if isStringSliceType(v.Type) {
			kept := make([]ast.Expr, 0, len(v.Elts))
			for _, e := range v.Elts {
				e = rewriteExpr(e, shouldRemove)
				if isRemoveStringLit(e, shouldRemove) {
					continue
				}
				kept = append(kept, e)
			}
			v.Elts = kept
			return v
		}
		for i, e := range v.Elts {
			v.Elts[i] = rewriteExpr(e, shouldRemove)
		}
		return v
	case *ast.KeyValueExpr:
		v.Key = rewriteExpr(v.Key, shouldRemove)
		v.Value = rewriteExpr(v.Value, shouldRemove)
		return v
	case *ast.ParenExpr:
		v.X = rewriteExpr(v.X, shouldRemove)
		return v
	case *ast.BinaryExpr:
		v.X = rewriteExpr(v.X, shouldRemove)
		v.Y = rewriteExpr(v.Y, shouldRemove)
		return v
	case *ast.UnaryExpr:
		v.X = rewriteExpr(v.X, shouldRemove)
		return v
	case *ast.SelectorExpr:
		v.X = rewriteExpr(v.X, shouldRemove)
		return v
	case *ast.IndexExpr:
		v.X = rewriteExpr(v.X, shouldRemove)
		v.Index = rewriteExpr(v.Index, shouldRemove)
		return v
	case *ast.SliceExpr:
		v.X = rewriteExpr(v.X, shouldRemove)
		if v.Low != nil {
			v.Low = rewriteExpr(v.Low, shouldRemove)
		}
		if v.High != nil {
			v.High = rewriteExpr(v.High, shouldRemove)
		}
		if v.Max != nil {
			v.Max = rewriteExpr(v.Max, shouldRemove)
		}
		return v
	case *ast.TypeAssertExpr:
		v.X = rewriteExpr(v.X, shouldRemove)
		return v
	case *ast.StarExpr:
		v.X = rewriteExpr(v.X, shouldRemove)
		return v
	case *ast.FuncLit:
		rewriteBlock(v.Body, shouldRemove)
		return v
	default:
		return e
	}
}

func isRemoveStringLit(e ast.Expr, shouldRemove func(string) bool) bool {
	bl, ok := e.(*ast.BasicLit)
	if !ok || bl.Kind != token.STRING {
		return false
	}
	s, err := strconv.Unquote(bl.Value)
	if err != nil {
		return false
	}
	return shouldRemove(s)
}

func isCallIdentExpr(e ast.Expr, name string) bool {
	call, ok := e.(*ast.CallExpr)
	if ok {
		e = call.Fun
	}
	id, ok := e.(*ast.Ident)
	return ok && id.Name == name
}

func isStringSliceType(t ast.Expr) bool {
	at, ok := t.(*ast.ArrayType)
	if !ok {
		return false
	}
	if at.Len != nil {
		return false
	}
	id, ok := at.Elt.(*ast.Ident)
	return ok && id.Name == "string"
}

type remainingTag struct {
	tag string
	pos token.Position
}

func findRemaining(f *ast.File, fset *token.FileSet, shouldRemove func(string) bool) []remainingTag {
	var remaining []remainingTag
	ast.Inspect(f, func(n ast.Node) bool {
		switch v := n.(type) {
		case *ast.CallExpr:
			switch {
			case isCallIdentExpr(v.Fun, "append"):
				remaining = append(remaining, findInArgs(v.Args[1:], fset, shouldRemove)...)
			case isCallIdentExpr(v.Fun, "filterTags"):
				remaining = append(remaining, findInArgs(v.Args[1:], fset, shouldRemove)...)
			}
		case *ast.CompositeLit:
			if isStringSliceType(v.Type) {
				remaining = append(remaining, findInArgs(v.Elts, fset, shouldRemove)...)
			}
		}
		return true
	})
	return remaining
}

func findInArgs(args []ast.Expr, fset *token.FileSet, shouldRemove func(string) bool) []remainingTag {
	var remaining []remainingTag
	for _, a := range args {
		bl, ok := a.(*ast.BasicLit)
		if !ok || bl.Kind != token.STRING {
			continue
		}
		s, err := strconv.Unquote(bl.Value)
		if err != nil {
			continue
		}
		if shouldRemove(s) {
			remaining = append(remaining, remainingTag{tag: s, pos: fset.Position(bl.Pos())})
		}
	}
	return remaining
}
