package main

// JavaScript lexer producing a token stream. Per §96, analysis must not rely
// solely on regular expressions: this lexer understands strings, template
// literals, regex literals and comments, so patterns inside string literals or
// comments are NOT misreported as code. It is a lexer, not a full parser;
// see LIMITATIONS.md for the honest scope of "token-level structural analysis".

import (
        "strings"
        "unicode"
        "unicode/utf8"
)

type TokType int

const (
        TokEOF TokType = iota
        TokIdent
        TokKeyword
        TokNumber
        TokString    // '...' or "..."
        TokTemplate  // `...`
        TokRegex
        TokPunct
        TokComment
)

type Token struct {
        Type TokType
        Val  string // raw text
        Str  string // cooked value for strings/templates
        Line int
}

var jsKeywords = map[string]bool{
        "var": true, "let": true, "const": true, "function": true, "return": true,
        "if": true, "else": true, "for": true, "while": true, "do": true,
        "switch": true, "case": true, "default": true, "break": true, "continue": true,
        "new": true, "delete": true, "typeof": true, "instanceof": true, "in": true,
        "void": true, "throw": true, "try": true, "catch": true,
        "finally": true, "class": true, "extends": true, "super": true, "this": true,
        "yield": true, "await": true, "import": true, "export": true,
        "true": true, "false": true, "null": true, "undefined": true,
}

// NOTE: contextual keywords (get, set, of, as, from, async, static) are
// intentionally NOT keywords here — they appear constantly as member names
// (chrome.storage.local.set, chrome.tabs.get, ...) and must remain chainable
// identifiers for API detection.

// regexAfterKW: keywords after which '/' begins a regex literal.
var regexAfterKW = map[string]bool{
        "return": true, "typeof": true, "instanceof": true, "in": true,
        "new": true, "delete": true, "void": true, "case": true, "do": true,
        "else": true, "yield": true, "await": true,
}

type Lexer struct {
        src  string
        pos  int
        line int
}

func NewLexer(src string) *Lexer { return &Lexer{src: src, line: 1} }

func (lx *Lexer) peek() byte {
        if lx.pos < len(lx.src) {
                return lx.src[lx.pos]
        }
        return 0
}

func (lx *Lexer) peekAt(n int) byte {
        if lx.pos+n < len(lx.src) {
                return lx.src[lx.pos+n]
        }
        return 0
}

func (lx *Lexer) advance() byte {
        c := lx.src[lx.pos]
        lx.pos++
        if c == '\n' {
                lx.line++
        }
        return c
}

// Lex tokenizes the whole source. It is best-effort tolerant: unknown bytes
// are skipped so a malformed file never crashes the scanner (§56).
func (lx *Lexer) Lex() []Token {
        var toks []Token
        for lx.pos < len(lx.src) {
                c := lx.peek()
                startLine := lx.line
                switch {
                case c == ' ' || c == '\t' || c == '\r' || c == '\n':
                        lx.advance()
                case c == '/' && lx.peekAt(1) == '/':
                        lx.skipLineComment(&toks, startLine)
                case c == '/' && lx.peekAt(1) == '*':
                        lx.skipBlockComment(&toks, startLine)
                case c == '\'' || c == '"':
                        lx.lexString(&toks, startLine)
                case c == '`':
                        lx.lexTemplate(&toks, startLine)
                case c == '/' && lx.regexAllowed(toks):
                        lx.lexRegex(&toks, startLine)
                case isDigit(c) || (c == '.' && isDigit(lx.peekAt(1))):
                        lx.lexNumber(&toks, startLine)
                case isIdentStart(runeAt(lx.src, lx.pos)):
                        lx.lexIdent(&toks, startLine)
                default:
                        lx.lexPunct(&toks, startLine)
                }
        }
        toks = append(toks, Token{Type: TokEOF, Line: lx.line})
        return toks
}

func (lx *Lexer) skipLineComment(toks *[]Token, line int) {
        start := lx.pos
        for lx.pos < len(lx.src) && lx.peek() != '\n' {
                lx.advance()
        }
        *toks = append(*toks, Token{Type: TokComment, Val: lx.src[start:lx.pos], Line: line})
}

func (lx *Lexer) skipBlockComment(toks *[]Token, line int) {
        start := lx.pos
        lx.advance()
        lx.advance()
        for lx.pos < len(lx.src) {
                if lx.peek() == '*' && lx.peekAt(1) == '/' {
                        lx.advance()
                        lx.advance()
                        break
                }
                lx.advance()
        }
        *toks = append(*toks, Token{Type: TokComment, Val: lx.src[start:lx.pos], Line: line})
}

func (lx *Lexer) lexString(toks *[]Token, line int) {
        quote := lx.advance()
        start := lx.pos
        var cooked strings.Builder
        for lx.pos < len(lx.src) {
                c := lx.peek()
                if c == '\\' {
                        lx.advance()
                        if lx.pos < len(lx.src) {
                                esc := lx.advance()
                                cooked.WriteString(unescapeJS(esc, lx))
                        }
                        continue
                }
                if c == quote {
                        lx.advance()
                        break
                }
                if c == '\n' { // unterminated string; bail gracefully
                        break
                }
                cooked.WriteByte(c)
                lx.advance()
        }
        *toks = append(*toks, Token{Type: TokString, Val: lx.src[start:lx.pos], Str: cooked.String(), Line: line})
}

func (lx *Lexer) lexTemplate(toks *[]Token, line int) {
        lx.advance() // `
        start := lx.pos
        var cooked strings.Builder
        depth := 0
        for lx.pos < len(lx.src) {
                c := lx.peek()
                if c == '\\' {
                        lx.advance()
                        if lx.pos < len(lx.src) {
                                esc := lx.advance()
                                cooked.WriteString(unescapeJS(esc, lx))
                        }
                        continue
                }
                if c == '`' && depth == 0 {
                        lx.advance()
                        break
                }
                if c == '$' && lx.peekAt(1) == '{' {
                        depth++
                        lx.advance()
                        lx.advance()
                        cooked.WriteString("${")
                        continue
                }
                if c == '}' && depth > 0 {
                        depth--
                        lx.advance()
                        cooked.WriteString("}")
                        continue
                }
                cooked.WriteByte(c)
                lx.advance()
        }
        *toks = append(*toks, Token{Type: TokTemplate, Val: lx.src[start:lx.pos], Str: cooked.String(), Line: line})
}

func (lx *Lexer) lexRegex(toks *[]Token, line int) {
        start := lx.pos
        lx.advance() // '/'
        inClass := false
        for lx.pos < len(lx.src) {
                c := lx.peek()
                if c == '\\' {
                        lx.advance()
                        if lx.pos < len(lx.src) {
                                lx.advance()
                        }
                        continue
                }
                if c == '[' {
                        inClass = true
                } else if c == ']' {
                        inClass = false
                } else if c == '/' && !inClass {
                        lx.advance()
                        // flags
                        for lx.pos < len(lx.src) && isIdentChar(runeAt(lx.src, lx.pos)) {
                                lx.advance()
                        }
                        break
                } else if c == '\n' {
                        break // not a regex after all; tolerate
                }
                lx.advance()
        }
        *toks = append(*toks, Token{Type: TokRegex, Val: lx.src[start:lx.pos], Line: line})
}

func (lx *Lexer) lexNumber(toks *[]Token, line int) {
        start := lx.pos
        for lx.pos < len(lx.src) {
                c := lx.peek()
                if isDigit(c) || c == '.' || c == 'x' || c == 'X' || c == 'e' || c == 'E' ||
                        ((c == '+' || c == '-') && (lx.src[lx.pos-1] == 'e' || lx.src[lx.pos-1] == 'E')) ||
                        (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') {
                        lx.advance()
                } else {
                        break
                }
        }
        *toks = append(*toks, Token{Type: TokNumber, Val: lx.src[start:lx.pos], Line: line})
}

func (lx *Lexer) lexIdent(toks *[]Token, line int) {
        start := lx.pos
        for lx.pos < len(lx.src) && isIdentChar(runeAt(lx.src, lx.pos)) {
                _, size := utf8.DecodeRuneInString(lx.src[lx.pos:])
                lx.pos += size
        }
        word := lx.src[start:lx.pos]
        t := Token{Type: TokIdent, Val: word, Line: line}
        if jsKeywords[word] {
                t.Type = TokKeyword
        }
        *toks = append(*toks, t)
}

func (lx *Lexer) lexPunct(toks *[]Token, line int) {
        start := lx.pos
        // multi-char punctuators (order matters)
        for _, p := range []string{"===", "!==", "**=", "...", "<<=", ">>=", ">>>", "&&=", "||=", "??=",
                "==", "!=", "<=", ">=", "&&", "||", "??", "?.", "++", "--", "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "=>", "<<", ">>"} {
                if strings.HasPrefix(lx.src[lx.pos:], p) {
                        for i := 0; i < len(p); i++ {
                                lx.advance()
                        }
                        *toks = append(*toks, Token{Type: TokPunct, Val: p, Line: line})
                        return
                }
        }
        c := lx.advance()
        _ = start
        *toks = append(*toks, Token{Type: TokPunct, Val: string(c), Line: line})
}

// regexAllowed decides whether '/' begins a regex or is division, based on the
// previous significant token (standard lexer heuristic).
func (lx *Lexer) regexAllowed(toks []Token) bool {
        for i := len(toks) - 1; i >= 0; i-- {
                t := toks[i]
                if t.Type == TokComment {
                        continue
                }
                switch t.Type {
                case TokIdent, TokNumber, TokString, TokTemplate, TokRegex:
                        return false
                case TokKeyword:
                        return regexAfterKW[t.Val]
                case TokPunct:
                        switch t.Val {
                        case ")", "]", "}":
                                return false // usually division
                        }
                        return true
                }
        }
        return true
}

func unescapeJS(esc byte, lx *Lexer) string {
        switch esc {
        case 'n':
                return "\n"
        case 't':
                return "\t"
        case 'r':
                return "\r"
        case 'b':
                return "\b"
        case 'f':
                return "\f"
        case 'v':
                return "\v"
        case '0':
                return "\x00"
        case '\n':
                return ""
        case 'x':
                if lx.pos+1 < len(lx.src) {
                        h := lx.src[lx.pos : lx.pos+2]
                        lx.pos += 2
                        return h // keep raw; sufficient for heuristic analysis
                }
                return "x"
        case 'u':
                if lx.pos+1 < len(lx.src) {
                        h := lx.src[lx.pos:min(lx.pos+4, len(lx.src))]
                        lx.pos += len(h)
                        return h
                }
                return "u"
        default:
                return string(esc)
        }
}

func isDigit(c byte) bool      { return c >= '0' && c <= '9' }
func isIdentStart(r rune) bool { return r == '_' || r == '$' || unicode.IsLetter(r) }

func runeAt(s string, i int) rune {
        if i >= len(s) {
                return 0
        }
        r, _ := utf8.DecodeRuneInString(s[i:])
        return r
}

func min(a, b int) int {
        if a < b {
                return a
        }
        return b
}

// significantTokens filters comments out for pattern walking.
func significantTokens(toks []Token) []Token {
        out := make([]Token, 0, len(toks))
        for _, t := range toks {
                if t.Type != TokComment {
                        out = append(out, t)
                }
        }
        return out
}
