package trace

import (
	"bytes"
	"fmt"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type RawTrace struct {
	Idx   int
	Trace string
}

type TokenType int

const (
	LP      TokenType = iota // Left Paren: (
	RP                       // Right Paren: )
	LCB                      // Left Curly Bracket: {
	RCB                      // Right Curly Bracket: }
	LSB                      // Left Square Bracket: [
	RSB                      // Right Square Bracket: ]
	COMMA                    // Comma: ,
	EQ                       // Equal: =
	MUL                      // Multiply: *
	OR                       // Or: or
	RA                       // Right Arrow: ->
	RAB                      // Right Arrow Bold: =>
	DOT                      // Dot: .
	SUB                      // Subtract: -
	ADD                      // Add: +
	DIV                      // Div: /
	DEREF                    // Dereference: &
	AT                       // At: @
	LS                       // Left Shift: <<
	NUMSIGN                  // Numsign: #
	COLON                    // Colon: :
	TILDE                    // ~
	STR                      // String: "abc"
	INT                      // Integer: 123|0xbeef
	ID                       // Variable
	NONE
)
const (
	maxParseLength = 4 * (1 << 20)
)

type Rule struct {
	Expr string
	Ty   TokenType
}

type Token struct {
	Ty  TokenType
	Val string
	Pos int
}

type AST interface {
	IsNil() bool
	Serialze(bool) string
	Children() []AST
	SetND(bool)
	IsND() bool
}

type NdOp struct {
	Tok Token
	Nd  bool
}

type NdInt struct {
	Tok Token
	Nd  bool
}

type NdString struct {
	Tok Token
	Nd  bool
}

type NdID struct {
	Tok Token
	Nd  bool
}

type NdIndex struct {
	Name *NdID
	Idx  AST
	Nd   bool
}

type NdList struct {
	V  []AST
	Nd bool
}

type NdFunc struct {
	Name *NdID
	Args *NdList
	Nd   bool
}

type NdInfixExpr struct {
	Op *NdOp
	L  AST
	R  AST
	Nd bool
}

type NdPrefixExpr struct {
	Op *NdOp
	R  AST
	Nd bool
}

type NdTrace struct {
	E     AST
	Errno *NdInt
	Nd    bool
}

func (n *NdOp) IsNil() bool             { return n == nil }
func (n *NdInt) IsNil() bool            { return n == nil }
func (n *NdString) IsNil() bool         { return n == nil }
func (n *NdID) IsNil() bool             { return n == nil }
func (n *NdList) IsNil() bool           { return n == nil }
func (n *NdIndex) IsNil() bool          { return n == nil }
func (n *NdFunc) IsNil() bool           { return n == nil }
func (n *NdInfixExpr) IsNil() bool      { return n == nil }
func (n *NdPrefixExpr) IsNil() bool     { return n == nil }
func (n *NdTrace) IsNil() bool          { return n == nil }
func (n *NdOp) Children() []AST         { return []AST{} }
func (n *NdInt) Children() []AST        { return []AST{} }
func (n *NdString) Children() []AST     { return []AST{} }
func (n *NdID) Children() []AST         { return []AST{} }
func (n *NdList) Children() []AST       { return append([]AST{}, n.V...) }
func (n *NdIndex) Children() []AST      { return []AST{n.Name, n.Idx} }
func (n *NdFunc) Children() []AST       { return []AST{n.Name, n.Args} }
func (n *NdInfixExpr) Children() []AST  { return []AST{n.L, n.Op, n.R} }
func (n *NdPrefixExpr) Children() []AST { return []AST{n.Op, n.R} }
func (n *NdTrace) Children() []AST      { return []AST{n.E, n.Errno} }
func (n *NdOp) SetND(f bool)            { n.Nd = f }
func (n *NdInt) SetND(f bool)           { n.Nd = f }
func (n *NdString) SetND(f bool)        { n.Nd = f }
func (n *NdID) SetND(f bool)            { n.Nd = f }
func (n *NdList) SetND(f bool)          { n.Nd = f }
func (n *NdIndex) SetND(f bool)         { n.Nd = f }
func (n *NdFunc) SetND(f bool)          { n.Nd = f }
func (n *NdInfixExpr) SetND(f bool)     { n.Nd = f }
func (n *NdPrefixExpr) SetND(f bool)    { n.Nd = f }
func (n *NdTrace) SetND(f bool)         { n.Nd = f }
func (n *NdOp) IsND() bool              { return n.Nd }
func (n *NdInt) IsND() bool             { return n.Nd }
func (n *NdString) IsND() bool          { return n.Nd }
func (n *NdID) IsND() bool              { return n.Nd }
func (n *NdList) IsND() bool            { return n.Nd }
func (n *NdIndex) IsND() bool           { return n.Nd }
func (n *NdFunc) IsND() bool            { return n.Nd }
func (n *NdInfixExpr) IsND() bool       { return n.Nd }
func (n *NdPrefixExpr) IsND() bool      { return n.Nd }
func (n *NdTrace) IsND() bool           { return n.Nd }

const ndPlaceHolder = "ND"

func (n *NdString) Serialze(dtm bool) string {
	if dtm && n.IsND() {
		return ndPlaceHolder
	}
	if n.IsNil() {
		return ""
	}
	return n.Tok.Val
}
func (n *NdInt) Serialze(dtm bool) string {
	if dtm && n.IsND() {
		return ndPlaceHolder
	}
	if n.IsNil() {
		return ""
	}
	return n.Tok.Val
}
func (n *NdOp) Serialze(dtm bool) string {
	if dtm && n.IsND() {
		return ndPlaceHolder
	}
	if n.IsNil() {
		return ""
	}
	return n.Tok.Val
}
func (n *NdID) Serialze(dtm bool) string {
	if dtm && n.IsND() {
		return ndPlaceHolder
	}
	if n.IsNil() {
		return ""
	}
	return n.Tok.Val
}
func (n *NdIndex) Serialze(dtm bool) string {
	if dtm && n.IsND() {
		return ndPlaceHolder
	}
	if n.IsNil() {
		return ""
	}
	return n.Name.Serialze(dtm) + `[` + n.Idx.Serialze(dtm) + `]`
}
func (n *NdList) Serialze(dtm bool) (s string) {
	s = ""
	if dtm && n.IsND() {
		s = ndPlaceHolder
		return
	}
	if n.IsNil() {
		return
	}
	s += `{`
	for _, e := range n.V {
		s += e.Serialze(dtm) + `, `
	}
	s += `}`
	return
}
func (n *NdFunc) Serialze(dtm bool) string {
	if dtm && n.IsND() {
		return ndPlaceHolder
	}
	if n.IsNil() {
		return ""
	}
	return n.Name.Serialze(dtm) + `(` + n.Args.Serialze(dtm) + `)`
}
func (n *NdInfixExpr) Serialze(dtm bool) string {
	if dtm && n.IsND() {
		return ndPlaceHolder
	}
	if n.IsNil() {
		return ""
	}
	return n.L.Serialze(dtm) + n.Op.Serialze(dtm) + n.R.Serialze(dtm)
}
func (n *NdPrefixExpr) Serialze(dtm bool) string {
	if dtm && n.IsND() {
		return ndPlaceHolder
	}
	if n.IsNil() {
		return ""
	}
	return n.Op.Serialze(dtm) + n.R.Serialze(dtm)
}
func (n *NdTrace) Serialze(dtm bool) string {
	if dtm && n.IsND() {
		return ndPlaceHolder
	}
	if n.IsNil() {
		return ""
	}
	return n.E.Serialze(dtm) + ` {` + n.Errno.Serialze(dtm) + `}`
}

type TokenStream struct {
	t   []Token
	pos int
}

type ProgSCTrace struct {
	Raw    []RawTrace
	Traces []*NdTrace
}

func (s *TokenStream) end() bool {
	return s.pos == len(s.t)
}

func (s *TokenStream) pop() (tk Token, err error) {
	if s.pos >= len(s.t) {
		err = fmt.Errorf("token stream out of bound")
		return
	}
	tk = s.t[s.pos]
	s.pos++
	return
}

func (s *TokenStream) top() (tk Token, err error) {
	if s.pos >= len(s.t) {
		err = fmt.Errorf("token stream out of bound")
		return
	}
	return s.t[s.pos], nil
}

func getList(s *TokenStream, lty, rty TokenType) (e *NdList, err error) {
	var nxt Token
	e = nil
	nxt, err = s.top()
	if err != nil {
		return
	}
	if nxt.Ty == lty {
		s.pop()
	} else {
		return
	}
	var l []AST
	for {
		var exp AST
		exp, err = getExpr(s)
		if err != nil {
			return
		}
		if exp.IsNil() {
			break
		}
		l = append(l, exp)
		nxt, err = s.top()
		if err != nil {
			return
		}
		if nxt.Ty == COMMA {
			s.pop()
		}
	}
	nxt, err = s.pop()
	if err != nil {
		return
	}
	if nxt.Ty != rty {
		err = fmt.Errorf("list paren/bracket does not match")
		return
	}
	e = &NdList{V: l}

	return
}

// TODO: think about if we should merge index into list
func getFuncOrIDOrIndex(s *TokenStream) (e AST, err error) {
	var nilptr *NdFunc = nil
	var nxt Token
	e = nilptr

	nxt, err = s.top()
	if err != nil {
		return
	}
	if nxt.Ty != ID {
		return
	}

	nxt, err = s.pop()
	if err != nil {
		return
	}
	ndID := &NdID{Tok: nxt}
	if s.end() {
		e = ndID
		return
	}
	pos := s.pos
	nxt, err = s.top()
	if err != nil {
		return
	}
	if nxt.Ty == LSB {
		s.pop()
		var exp AST
		exp, err = getExpr(s)
		if err != nil {
			return
		}
		if exp.IsNil() {
			s.pos = pos
		} else {
			nxt, err = s.top()
			if err != nil {
				return
			}
			if nxt.Ty == RSB {
				s.pop()
				e = &NdIndex{Name: ndID, Idx: exp}
				return
			} else {
				// a expression like this could be possible?
				// [a [1 2] ]
				// thus we do not report error
				s.pos = pos
			}
		}
	}
	var l *NdList
	l, err = getList(s, LP, RP)
	if err != nil {
		return
	}
	if l == nil {
		e = ndID
		return
	}
	e = &NdFunc{Name: ndID, Args: l}
	return
}
func getString(s *TokenStream) (e *NdString, err error) {
	var nxt Token
	e = nil

	nxt, err = s.top()
	if err != nil {
		return
	}
	if nxt.Ty == STR {
		nxt, err = s.pop()
		if err != nil {
			return
		}
		e = &NdString{Tok: nxt}
	}
	return
}
func getInt(s *TokenStream) (e *NdInt, err error) {
	var nxt Token
	e = nil

	nxt, err = s.top()
	if err != nil {
		return
	}
	if nxt.Ty == INT {
		nxt, err = s.pop()
		if err != nil {
			return
		}
		e = &NdInt{Tok: nxt}
	}
	return
}
func getInfixExpr(s *TokenStream) (e AST, err error) {
	var nxt Token
	var nilptr *NdInfixExpr = nil
	e = nilptr

	var l, r AST
	var inOp *NdOp

	l, err = getInt(s)
	if err != nil {
		return
	}
	if !l.IsNil() {
		goto MATCH_L
	}

	l, err = getString(s)
	if err != nil {
		return
	}
	if !l.IsNil() {
		goto MATCH_L
	}

	l, err = getFuncOrIDOrIndex(s)
	if err != nil {
		return
	}
	if !l.IsNil() {
		goto MATCH_L
	}

	l, err = getList(s, LSB, RSB)
	if err != nil {
		return
	}
	if !l.IsNil() {
		goto MATCH_L
	}

	l, err = getList(s, LCB, RCB)
	if err != nil {
		return
	}
	if !l.IsNil() {
		goto MATCH_L
	}

	return

MATCH_L:
	if s.end() {
		e = l
		return
	}
	nxt, err = s.top()
	if err != nil {
		return
	}
	switch nxt.Ty {
	case ADD, SUB, MUL, DIV, OR, EQ, RA, RAB, LS, COLON:
		nxt, err = s.pop()
		if err != nil {
			return
		}
		inOp = &NdOp{Tok: nxt}
	default:
		e = l
		return
	}

	r, err = getExpr(s)
	if r.IsNil() {
		return
	}
	e = &NdInfixExpr{
		Op: inOp,
		L:  l,
		R:  r,
	}
	return
}
func getPrefixExpr(s *TokenStream) (e *NdPrefixExpr, err error) {
	var nxt Token
	e = nil

	var preOp NdOp
	var r AST

	nxt, err = s.top()
	if err != nil {
		return
	}
	switch nxt.Ty {
	case SUB, DEREF, AT, TILDE:
		nxt, err = s.pop()
		if err != nil {
			return
		}
		preOp = NdOp{Tok: nxt}
	default:
		return
	}
	r, err = getExpr(s)
	if r.IsNil() {
		if err == nil {
			err = fmt.Errorf("prefix expression: expected expression")
		}
		return
	}
	e = &NdPrefixExpr{
		Op: &preOp,
		R:  r,
	}
	return
}
func getExpr(s *TokenStream) (e AST, err error) {
	var nxt Token
	var nilptr *NdInfixExpr = nil
	e = nilptr

	nxt, err = s.top()
	if err != nil {
		return
	}
	if nxt.Ty == LP {
		s.pop()
		e, err = getExpr(s)
		if err != nil {
			return
		}
		if e.IsNil() {
			err = fmt.Errorf("cannot match expression after '('")
			return
		}
		nxt, err = s.pop()
		if err != nil {
			return
		}
		if nxt.Ty != RP {
			err = fmt.Errorf("expecting ')'")
			return
		}
		return
	}
	e, err = getInfixExpr(s)
	if err != nil || !e.IsNil() {
		return
	}
	e, err = getPrefixExpr(s)
	if err != nil || !e.IsNil() {
		return
	}

	return
}

func Parse(s *TokenStream) (t *NdTrace, err error) {
	var nxt Token
	var e AST
	e, err = getExpr(s)
	if err != nil {
		return
	}

	if e.IsNil() {
		err = fmt.Errorf("syscall trace: cannot match expression")
		return
	}
	t = &NdTrace{E: e}
	nxt, err = s.pop()
	if err != nil {
		return
	}
	if nxt.Ty != LCB {
		err = fmt.Errorf("syscall trace: expected '{' for errno")
		return
	}
	nxt, err = s.top()
	if err != nil {
		return
	}
	if nxt.Ty != INT {
		err = fmt.Errorf("syscall trace: expected integer errno")
		return
	}
	nxt, err = s.pop()
	if err != nil {
		return
	}
	errno := &NdInt{Tok: nxt}
	nxt, err = s.pop()
	if err != nil {
		return
	}
	if nxt.Ty != RCB {
		err = fmt.Errorf("syscall trace: expected '}' for errno")
		return
	}
	t.Errno = errno

	return
}

// In init, all regex expressions will add a `^`
var rules = []Rule{
	{`[ \n\t\r]+`, NONE},
	{`\.\.\.`, NONE},
	// observed case: ioctl(3, SIOCGIFCONF, {ifc_len=2 * sizeof(struct ifreq), ifc_buf=NULL}) = 0
	{`struct`, NONE}, // ignore struct keyword
	{`/\*.*?\*/`, NONE},
	// restart_syscall(<... resuming interrupted system call ...>) = -1 (4)
	{`<\.\.\..*?\.\.\.>`, NONE},
	{`\(`, LP},
	{`\)`, RP},
	{`{`, LCB},
	{`}`, RCB},
	{`\[`, LSB},
	{`\]`, RSB},
	{`,`, COMMA},
	// observed that in some ioctl traces there is '{x=y, ...} => {m=n, ...}'
	{`=>`, RAB},
	{`=`, EQ},
	{`\*`, MUL},
	{`or`, OR},
	{`\|`, OR},
	{`->`, RA},
	{`\.`, DOT},
	{`\-`, SUB},
	{`\+`, ADD},
	{`/`, DIV},
	{`&`, DEREF},
	// observed case: sun_path=@"..."
	{`@`, AT},
	{`<<`, LS},
	{`#`, NUMSIGN},
	{`:`, COLON},
	// ~[INT QUIT]
	{`~`, TILDE},
	// 0x1234
	{`(0x)?[\dA-Fa-f]+\b|\d+\b`, INT},
	// "xxxx", "xyz\d\"abc"
	{`\"(\\.|[^\"\\])*\"`, STR},
	// 'xxxx'
	{`\'(\\.|[^\'\\])*\'`, STR},
	// abc_def
	{`[a-zA-Z_][a-zA-Z0-9_\$]*`, ID},
	// , cmsg_data=???
	{`\?\?\?`, ID},
}

var regexprs []*regexp.Regexp

func init() {
	for _, rule := range rules {
		regexprs = append(regexprs, regexp.MustCompile(`^(`+rule.Expr+`)`))
	}
}

func Lex(s string) (ts *TokenStream, err error) {
	var t []Token
	pos := 0
	l := len(s)
	for pos < l {
		match := false
		for i, re := range regexprs {
			v := re.FindString(s[pos:])
			if len(v) > 0 {
				if rules[i].Ty != NONE {
					t = append(t,
						Token{
							Ty:  rules[i].Ty,
							Pos: pos,
							Val: v,
						})
				}
				pos += len(v)
				match = true
				break
			}
		}
		if !match {
			printLen := 30
			if pos+printLen > len(s) {
				printLen = len(s) - pos
			}
			err = fmt.Errorf("match fail: %v ", s[pos:pos+printLen])
			return
		}
	}
	ts = &TokenStream{
		t:   t,
		pos: 0,
	}
	return
}

func ReadSCTrace(sc []string) (t []RawTrace, err error) {
	for _, s := range sc {
		rt := RawTrace{}
		sp := strings.SplitN(strings.Trim(s, " \n\t\r"), ":", 2)
		if len(sp) != 2 {
			continue
		}
		rt.Idx, err = strconv.Atoi(sp[0])
		if err != nil {
			return nil, fmt.Errorf("cannot get index from %v: %v", sp[0], err)
		}
		rt.Trace = strings.Trim(sp[1], " \n\t\r")
		t = append(t, rt)
	}
	sort.Slice(t, func(i, j int) bool {
		return t[i].Idx < t[j].Idx
	})
	return
}

func TraceNDUpdate(cand, b AST) (updated bool) {
	if cand.IsND() {
		return false
	}
	if reflect.TypeOf(cand) != reflect.TypeOf(b) {
		cand.SetND(true)
		return true
	}
	candChildren, bChildren := cand.Children(), b.Children()
	// E.g. NDList
	if len(candChildren) != len(bChildren) {
		cand.SetND(true)
		return true
	}
	if len(candChildren) == 0 {
		switch cand.(type) {
		case *NdOp:
			nc, nb := cand.(*NdOp), b.(*NdOp)
			if nc.Tok.Val != nb.Tok.Val {
				nc.SetND(true)
				return true
			}
		case *NdInt:
			nc, nb := cand.(*NdInt), b.(*NdInt)
			if nc.Tok.Val != nb.Tok.Val {
				nc.SetND(true)
				return true
			}
		case *NdString:
			nc, nb := cand.(*NdString), b.(*NdString)
			if nc.Tok.Val != nb.Tok.Val {
				nc.SetND(true)
				return true
			}
		case *NdID:
			nc, nb := cand.(*NdID), b.(*NdID)
			if nc.Tok.Val != nb.Tok.Val {
				nc.SetND(true)
				return true
			}
		default:
			// should not go here!
		}
		return false
	}
	for i, ac := range candChildren {
		updated = updated || TraceNDUpdate(ac, bChildren[i])
	}
	return updated
}

type SCTraceDiff struct {
	CallIdx  int    `json:"call_idx"`
	NodePath string `json:"node_path"`
	D        string `json:"d"`
	T        string `json:"t"`
}

func TraceNDEqual(cand, b AST, nodePath string, diff []*SCTraceDiff) (bool, []*SCTraceDiff) {
	if cand.IsND() {
		return true, diff
	}
	if reflect.TypeOf(cand) != reflect.TypeOf(b) {
		return false, append(diff, &SCTraceDiff{NodePath: nodePath, D: cand.Serialze(false), T: b.Serialze(false)})
	}
	candChildren, bChildren := cand.Children(), b.Children()
	// E.g. NDList
	if len(candChildren) != len(bChildren) {
		return false, append(diff, &SCTraceDiff{NodePath: nodePath, D: cand.Serialze(false), T: b.Serialze(false)})
	}
	if len(candChildren) == 0 {
		switch cand.(type) {
		case *NdOp:
			nc, nb := cand.(*NdOp), b.(*NdOp)
			if nc.Tok.Val != nb.Tok.Val {
				return false, append(diff, &SCTraceDiff{NodePath: nodePath, D: cand.Serialze(false), T: b.Serialze(false)})
			}
		case *NdInt:
			nc, nb := cand.(*NdInt), b.(*NdInt)
			if nc.Tok.Val != nb.Tok.Val {
				return false, append(diff, &SCTraceDiff{NodePath: nodePath, D: cand.Serialze(false), T: b.Serialze(false)})
			}
		case *NdString:
			nc, nb := cand.(*NdString), b.(*NdString)
			if nc.Tok.Val != nb.Tok.Val {
				return false, append(diff, &SCTraceDiff{NodePath: nodePath, D: cand.Serialze(false), T: b.Serialze(false)})
			}
		case *NdID:
			nc, nb := cand.(*NdID), b.(*NdID)
			if nc.Tok.Val != nb.Tok.Val {
				return false, append(diff, &SCTraceDiff{NodePath: nodePath, D: cand.Serialze(false), T: b.Serialze(false)})
			}
		default:
			// should not go here!
		}
		return true, diff
	}
	equal := true
	for i, ac := range candChildren {
		var childEqual bool
		childEqual, diff = TraceNDEqual(ac, bChildren[i], fmt.Sprintf("%v.%v", nodePath, i), diff)
		equal = equal && childEqual
	}
	return equal, diff
}

func ProgSCTraceNDEqual(a, b *ProgSCTrace) (equal bool, diff []*SCTraceDiff) {
	equal = true
	for i, ta := range a.Traces {
		if ta.E.IsNil() && ta.Nd {
			continue
		}
		if i >= len(b.Traces) {
			equal = false
			diff = append(diff, &SCTraceDiff{NodePath: "$", CallIdx: a.Raw[i].Idx, D: a.Raw[i].Trace, T: ""})
			continue
		}
		if b.Traces[i].E.IsNil() && b.Traces[i].Nd {
			continue
		}
		if (ta.E.IsNil() || b.Traces[i].E.IsNil()) || (a.Raw[i].Idx != b.Raw[i].Idx) {
			equal = (a.Raw[i].Trace == b.Raw[i].Trace)
			if !equal {
				diff = append(diff, &SCTraceDiff{NodePath: "$", CallIdx: a.Raw[i].Idx, D: a.Raw[i].Trace, T: b.Raw[i].Trace})
			}
			continue
		}
		var callEqual bool
		oldDiffLen := len(diff)
		callEqual, diff = TraceNDEqual(ta, b.Traces[i], "$", diff)
		for j := oldDiffLen; j < len(diff); j++ {
			diff[j].CallIdx = i
		}
		equal = callEqual && equal
	}
	if len(a.Traces) < len(b.Traces) {
		equal = false
		for i := len(a.Traces); i < len(b.Traces); i++ {
			diff = append(diff, &SCTraceDiff{NodePath: "$", CallIdx: b.Raw[i].Idx, D: "", T: b.Raw[i].Trace})
		}
	}
	return equal, diff
}

func ProgSCTraceNDUpdate(cand *ProgSCTrace, b *ProgSCTrace) (nomatch bool, updated bool) {
	if len(cand.Traces) != len(b.Traces) {
		nomatch = true
		return
	}

	for i, ta := range cand.Traces {
		if ta.E.IsNil() || b.Traces[i].E.IsNil() {
			if !ta.E.IsNil() {
				var x *NdInfixExpr = nil
				ta.E = x
				ta.Errno = nil
				ta.Nd = false
				updated = true
			}
			if cand.Raw[i].Trace != b.Raw[i].Trace {
				ta.Nd = true
				updated = true
			}
			continue
		}
		updated = updated || TraceNDUpdate(ta, b.Traces[i])
	}
	return
}

func ParseSCTrace(sc []string) (trace *ProgSCTrace, err error) {
	var rawTraces []RawTrace
	var ts *TokenStream
	var traceLine *NdTrace
	rawTraces, err = ReadSCTrace(sc)
	if err != nil {
		return nil, fmt.Errorf("cannot read raw trace: %v", err)
	}
	trace = &ProgSCTrace{Raw: rawTraces}
	for _, raw := range rawTraces {
		if len(raw.Trace) < maxParseLength {
			ts, err = Lex(raw.Trace)
			if err != nil {
				return nil, fmt.Errorf("cannot lex syscall trace: %v", err)
			}
			traceLine, err = Parse(ts)
			if err != nil {
				var x *NdInfixExpr = nil
				traceLine = &NdTrace{
					E:     x,
					Errno: nil,
					Nd:    false,
				}
				err = nil
			}
		} else {
			var x *NdInfixExpr = nil
			traceLine = &NdTrace{
				E:     x,
				Errno: nil,
				Nd:    false,
			}
		}
		trace.Traces = append(trace.Traces, traceLine)
	}
	return

}

func (trace *ProgSCTrace) RawSerialze() []byte {
	buf := new(bytes.Buffer)
	for _, r := range trace.Raw {
		fmt.Fprintf(buf, "%v: %v\n", r.Idx, r.Trace)
	}
	return buf.Bytes()
}

func (trace *ProgSCTrace) DeterminSerialze() []byte {
	buf := new(bytes.Buffer)
	for i, t := range trace.Traces {
		if t.E.IsNil() {
			if t.Nd {
				fmt.Fprint(buf, "(RAW ND)")
			} else {
				fmt.Fprint(buf, "(RAW D)")
			}
			fmt.Fprintf(buf, "%v: %v\n", trace.Raw[i].Idx, trace.Raw[i])
		} else {
			fmt.Fprintf(buf, "%v: %v\n", trace.Raw[i].Idx, t.Serialze(true))
		}
	}
	return buf.Bytes()
}
