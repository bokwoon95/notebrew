package markdownmath

import (
	"bytes"
	"strings"

	"git.sr.ht/~mekyt/latex2mathml"
	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/parser"
	"github.com/yuin/goldmark/renderer"
	"github.com/yuin/goldmark/text"
	"github.com/yuin/goldmark/util"
)

var Extension = mathExtension{}

type mathExtension struct{}

func (e mathExtension) Extend(markdown goldmark.Markdown) {
	markdown.Parser().AddOptions(
		parser.WithASTTransformers(
			util.Prioritized(mathTransformer{}, 100),
		),
	)
	markdown.Renderer().AddOptions(
		renderer.WithNodeRenderers(
			util.Prioritized(mathRenderer{}, 100),
		),
	)
}

type mathNode struct {
	ast.BaseBlock
}

var mathKind = ast.NewNodeKind("math")

var _ ast.Node = (*mathNode)(nil)

func (n *mathNode) Kind() ast.NodeKind {
	return mathKind
}

func (n *mathNode) Dump(source []byte, level int) {
	ast.DumpHelper(n, source, level, nil, nil)
}

type mathTransformer struct{}

var _ parser.ASTTransformer = (*mathTransformer)(nil)

func (t mathTransformer) Transform(document *ast.Document, reader text.Reader, _ parser.Context) {
	var nodes []ast.Node
	ast.Walk(document, func(node ast.Node, entering bool) (ast.WalkStatus, error) {
		if !entering {
			return ast.WalkContinue, nil
		}
		fencedCodeBlock, ok := node.(*ast.FencedCodeBlock)
		if !ok {
			return ast.WalkContinue, nil
		}
		if !bytes.Equal(fencedCodeBlock.Language(reader.Source()), []byte("math")) {
			return ast.WalkContinue, nil
		}
		nodes = append(nodes, fencedCodeBlock)
		return ast.WalkContinue, nil
	})
	for _, node := range nodes {
		parent := node.Parent()
		if parent != nil {
			mathNode := &mathNode{}
			mathNode.SetLines(node.Lines())
			parent.ReplaceChild(parent, node, mathNode)
		}
	}
}

type mathRenderer struct{}

var _ renderer.NodeRenderer = (*mathRenderer)(nil)

func (r mathRenderer) RegisterFuncs(reg renderer.NodeRendererFuncRegisterer) {
	reg.Register(mathKind, func(w util.BufWriter, source []byte, node ast.Node, entering bool) (ast.WalkStatus, error) {
		if !entering {
			return ast.WalkContinue, nil
		}
		var length int
		mathNode := node.(*mathNode)
		lines := mathNode.Lines()
		for i := 0; i < lines.Len(); i++ {
			line := lines.At(i)
			length += len(line.Value(source))
		}
		var b strings.Builder
		b.Grow(length)
		for i := 0; i < lines.Len(); i++ {
			line := lines.At(i)
			b.Write(line.Value(source))
		}
		mathml := latex2mathml.Convert(b.String(), "http://www.w3.org/1998/Math/MathML", "block", 2)
		w.WriteString(mathml)
		return ast.WalkContinue, nil
	})
}
