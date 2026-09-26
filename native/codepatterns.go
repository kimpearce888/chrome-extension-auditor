package main

// Code pattern analysis over the token stream (§96). Structural call-site
// matching: identifiers, member chains, string arguments and numeric
// arguments are read from tokens, so patterns inside comments/strings are not
// misreported, and no code is ever executed (§53).

import (
        "fmt"
        "strconv"
        "strings"
)

type CodeSite struct {
        File string `json:"file"`
        Line int    `json:"line"`
        Kind string `json:"kind"`
        Arg  string `json:"arg,omitempty"`
}

type TimerSite struct {
        CodeSite
        DelayMS  float64 `json:"delayMs"`
        Interval bool    `json:"interval"`
}

type NetworkSite struct {
        CodeSite
        Method  string `json:"method"` // fetch|XHR|WebSocket|EventSource|sendBeacon
        URL     string `json:"url,omitempty"`
        Dynamic bool   `json:"dynamic"`
}

type ObserverSite struct {
        CodeSite
        Subtree   bool `json:"subtree"`
        ChildList bool `json:"childList"`
        Attributes bool `json:"attributes"`
}

// FileMetrics supports readability/minification heuristics (§36–38).
type FileMetrics struct {
        Bytes             int     `json:"bytes"`
        Lines             int     `json:"lines"`
        AvgLineLen        float64 `json:"avgLineLen"`
        MaxLineLen        int     `json:"maxLineLen"`
        IdentCount        int     `json:"identCount"`
        AvgIdentLen       float64 `json:"avgIdentLen"`
        FunctionCount     int     `json:"functionCount"`
        BackslashX        int     `json:"backslashX"`
        StringCount       int     `json:"stringCount"`
        LongStrings       int     `json:"longStrings"`
        AvgStringEntropy  float64 `json:"avgStringEntropy"`
        Base64Blobs       int     `json:"base64Blobs"`
        HexIdents         int     `json:"hexIdents"`
        SemicolonDensity  float64 `json:"semicolonDensity"`
}

// FileAnalysis is the cacheable per-file analysis result (§92).
type FileAnalysis struct {
        APIs            map[string]int      `json:"apis"`
        APIEvidence     map[string][]string `json:"apiEvidence"`
        Timers          []TimerSite         `json:"timers,omitempty"`
        StringCodeExec  []CodeSite          `json:"stringCodeExec,omitempty"`
        DomInjections   []CodeSite          `json:"domInjections,omitempty"`
        Observers       []ObserverSite      `json:"observers,omitempty"`
        NetworkCalls    []NetworkSite       `json:"networkCalls,omitempty"`
        DynamicURLs     []CodeSite          `json:"dynamicUrls,omitempty"`
        MessageHandlers []CodeSite          `json:"messageHandlers,omitempty"`
        ExternalHandlers []CodeSite         `json:"externalHandlers,omitempty"`
        PostMessage     []CodeSite          `json:"postMessage,omitempty"`
        NativeMsg       []CodeSite          `json:"nativeMsg,omitempty"`
        DynamicAccess   []CodeSite          `json:"dynamicAccess,omitempty"`
        ScriptInsert    []CodeSite          `json:"scriptInsert,omitempty"`
        EventListeners  int                 `json:"eventListeners"`
        DocQueries      int                 `json:"docQueries"`
        StorageCalls    int                 `json:"storageCalls"`
        ClipboardCalls  int                 `json:"clipboardCalls"`
        URLStrings      []CodeSite          `json:"urlStrings,omitempty"`
        Metrics         FileMetrics         `json:"metrics"`
}

// AnalyzeJS runs token-level analysis on one JS/TS source file.
func AnalyzeJS(file string, src string) *FileAnalysis {
        fa := &FileAnalysis{
                APIs:        map[string]int{},
                APIEvidence: map[string][]string{},
        }
        toks := significantTokens(NewLexer(src).Lex())

        for i := 0; i < len(toks); i++ {
                t := toks[i]
                if t.Type != TokIdent {
                        // post-observe scan for observer config happens in handleChain
                        continue
                }
                chain, next := dottedChain(toks, i)
                if len(chain) == 0 {
                        continue
                }
                i = next - 1
                handleChain(fa, file, chain, toks, next)
        }
        fa.URLStrings = CollectURLStrings(file, src)
        fa.Metrics = computeMetrics(file, src, toks)
        return fa
}

// dottedChain collects a.b.c chains starting at index i; returns the chain and
// the index just after the chain.
func dottedChain(toks []Token, i int) ([]string, int) {
        var chain []string
        for i < len(toks) && toks[i].Type == TokIdent {
                chain = append(chain, toks[i].Val)
                i++
                if i < len(toks) && toks[i].Type == TokPunct && toks[i].Val == "." {
                        i++
                        continue
                }
                break
        }
        return chain, i
}

// calledNow reports whether the token right after the chain is "(".
func calledNow(toks []Token, after int) bool {
        return after < len(toks) && toks[after].Type == TokPunct && toks[after].Val == "("
}

func (fa *FileAnalysis) addAPI(name, file string, line int) {
        fa.APIs[name]++
        fa.APIEvidence[name] = append(fa.APIEvidence[name], fmt.Sprintf("%s:%d", file, line))
        if len(fa.APIEvidence[name]) > 5 {
                fa.APIEvidence[name] = fa.APIEvidence[name][:5]
        }
}

func handleChain(fa *FileAnalysis, file string, chain []string, toks []Token, next int) {
        full := strings.Join(chain, ".")
        line := toks[next-1].Line
        isCall := calledNow(toks, next)

        // chrome.* / browser.* API inventory (static, dotted access)
        if (chain[0] == "chrome" || chain[0] == "browser") && len(chain) >= 2 {
                fa.addAPI(full, file, line)
        }

        // Dynamic API access: chrome[expr] / browser[expr] (§59)
        if len(chain) == 1 && (chain[0] == "chrome" || chain[0] == "browser") {
                if next < len(toks) && toks[next].Type == TokPunct && toks[next].Val == "[" {
                        kind := "chrome[variable]"
                        if next+1 < len(toks) && (toks[next+1].Type == TokString || toks[next+1].Type == TokTemplate) {
                                kind = "chrome[\"" + clampExcerpt(toks[next+1].Str) + "\"]"
                        }
                        fa.DynamicAccess = append(fa.DynamicAccess, CodeSite{File: file, Line: line, Kind: kind})
                }
        }

        switch full {
        case "chrome.runtime.onMessage.addListener":
                fa.MessageHandlers = append(fa.MessageHandlers, CodeSite{File: file, Line: line, Kind: "onMessage"})
                fa.addAPI(full, file, line)
        case "chrome.runtime.onMessageExternal.addListener":
                fa.ExternalHandlers = append(fa.ExternalHandlers, CodeSite{File: file, Line: line, Kind: "onMessageExternal"})
                fa.addAPI(full, file, line)
        case "chrome.runtime.onConnect.addListener":
                fa.MessageHandlers = append(fa.MessageHandlers, CodeSite{File: file, Line: line, Kind: "onConnect"})
                fa.addAPI(full, file, line)
        case "chrome.runtime.onConnectExternal.addListener":
                fa.ExternalHandlers = append(fa.ExternalHandlers, CodeSite{File: file, Line: line, Kind: "onConnectExternal"})
                fa.addAPI(full, file, line)
        case "chrome.runtime.connectNative", "chrome.runtime.sendNativeMessage":
                fa.NativeMsg = append(fa.NativeMsg, CodeSite{File: file, Line: line, Kind: full})
                fa.addAPI(full, file, line)
        case "MutationObserver":
                if isCall {
                        fa.Observers = append(fa.Observers, ObserverSite{CodeSite: CodeSite{File: file, Line: line, Kind: "new MutationObserver"}})
                }
        case "document.write", "document.writeln":
                if isCall {
                        fa.DomInjections = append(fa.DomInjections, CodeSite{File: file, Line: line, Kind: full})
                }
        case "document.createElement":
                if isCall {
                        if s := firstStringArg(toks, next); strings.EqualFold(s, "script") || strings.EqualFold(s, "iframe") {
                                fa.ScriptInsert = append(fa.ScriptInsert, CodeSite{File: file, Line: line, Kind: "createElement(" + s + ")"})
                        }
                }
        case "navigator.sendBeacon":
                if isCall {
                        fa.recordNetwork(file, line, "sendBeacon", toks, next)
                }
        case "window.postMessage", "postMessage":
                if isCall {
                        fa.PostMessage = append(fa.PostMessage, CodeSite{File: file, Line: line, Kind: "postMessage"})
                }
        case "fetch", "WebSocket", "EventSource":
                if isCall {
                        fa.recordNetwork(file, line, full, toks, next)
                }
        case "eval":
                if isCall {
                        fa.StringCodeExec = append(fa.StringCodeExec, CodeSite{File: file, Line: line, Kind: "eval"})
                }
        case "Function":
                if isCall {
                        fa.StringCodeExec = append(fa.StringCodeExec, CodeSite{File: file, Line: line, Kind: "new Function"})
                }
        case "setTimeout", "setInterval":
                if isCall {
                        fa.recordTimer(file, line, full == "setInterval", toks, next)
                }
        case "String.fromCharCode":
                fa.addAPI(full, file, line)
        case "atob", "btoa":
                if isCall {
                        fa.addAPI(full, file, line)
                }
        case "require":
                if isCall {
                        fa.addAPI(full, file, line)
                }
        }

        // Member-property behaviors
        if len(chain) >= 2 {
                prop := chain[len(chain)-1]
                switch prop {
                case "innerHTML", "outerHTML", "srcdoc":
                        if next < len(toks) && toks[next].Type == TokPunct && toks[next].Val == "=" {
                                fa.DomInjections = append(fa.DomInjections, CodeSite{File: file, Line: line, Kind: prop + " ="})
                        }
                case "insertAdjacentHTML":
                        if isCall {
                                fa.DomInjections = append(fa.DomInjections, CodeSite{File: file, Line: line, Kind: "insertAdjacentHTML"})
                        }
                case "addEventListener":
                        if isCall {
                                if s := firstStringArg(toks, next); s == "message" || s == "beforeunload" || s == "messageerror" {
                                        fa.MessageHandlers = append(fa.MessageHandlers, CodeSite{File: file, Line: line, Kind: "addEventListener(\"" + s + "\")"})
                                }
                                fa.EventListeners++
                        }
                case "observe":
                        if isCall {
                                // MutationObserver#observe(target, config) — parse the config flags
                                os := ObserverSite{CodeSite: CodeSite{File: file, Line: line, Kind: ".observe(...)"}}
                                depth := 0
                        for j := next; j < len(toks) && j < next+120; j++ {
                                        tk := toks[j]
                                        if tk.Type == TokPunct {
                                                if tk.Val == "(" || tk.Val == "[" || tk.Val == "{" {
                                                        depth++
                                                } else if tk.Val == ")" || tk.Val == "]" || tk.Val == "}" {
                                                        depth--
                                                        if depth <= 0 {
                                                                break
                                                        }
                                                }
                                                continue
                                        }
                                        if depth == 2 && tk.Type == TokIdent {
                                                switch tk.Val {
                                                case "subtree", "childList", "attributes", "attributeOldValue", "characterData":
                                                        // expect ':' true within the object literal
                                                        if next+0 < len(toks) && j+2 < len(toks) && toks[j+1].Val == ":" && toks[j+2].Val == "true" {
                                                                switch tk.Val {
                                                                case "subtree":
                                                                        os.Subtree = true
                                                                case "childList":
                                                                        os.ChildList = true
                                                                case "attributes", "attributeOldValue":
                                                                        os.Attributes = true
                                                                }
                                                        }
                                                }
                                        }
                                }
                                fa.Observers = append(fa.Observers, os)
                        }
                case "querySelectorAll", "getElementsByTagName", "getElementsByClassName":
                        if isCall {
                                fa.DocQueries++
                        }
                case "open":
                        if isCall {
                                // XHR .open(verb, url) — require an HTTP verb to avoid DB/Cache open()
                                verb := firstStringArg(toks, next)
                                switch strings.ToUpper(verb) {
                                case "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH":
                                        if u := nthStringArg(toks, next, 1); looksLikeURL(u) {
                                                fa.recordNetworkURL(file, line, "XHR", u)
                                        } else {
                                                fa.DynamicURLs = append(fa.DynamicURLs, CodeSite{File: file, Line: line, Kind: "XHR.open(variable)"})
                                        }
                                }
                        }
                }
        }

        // Named chrome storage APIs
        switch full {
        case "chrome.storage.local.get", "chrome.storage.local.set",
                "chrome.storage.sync.get", "chrome.storage.sync.set",
                "chrome.storage.session.get", "chrome.storage.session.set":
                fa.StorageCalls++
        case "navigator.clipboard.readText", "navigator.clipboard.writeText", "document.execCommand":
                fa.ClipboardCalls++
        }
}

// recordTimer reads setInterval/setTimeout( <arg>, <delay> ) — toks[openIdx] is "(".
func (fa *FileAnalysis) recordTimer(file string, line int, interval bool, toks []Token, openIdx int) {
        kind := "setTimeout"
        if interval {
                kind = "setInterval"
        }
        ts := TimerSite{CodeSite: CodeSite{File: file, Line: line, Kind: kind}, DelayMS: -1, Interval: interval}
        if openIdx+1 < len(toks) {
                first := toks[openIdx+1]
                if first.Type == TokString || first.Type == TokTemplate {
                        ts.Arg = clampExcerpt(first.Str)
                        fa.StringCodeExec = append(fa.StringCodeExec, CodeSite{File: file, Line: line, Kind: kind + "(string)", Arg: clampExcerpt(first.Str)})
                }
                depth := 0
                for j := openIdx; j < len(toks) && j < openIdx+80; j++ {
                        tk := toks[j]
                        if tk.Type != TokPunct {
                                continue
                        }
                        if tk.Val == "(" || tk.Val == "[" || tk.Val == "{" {
                                depth++
                        } else if tk.Val == ")" || tk.Val == "]" || tk.Val == "}" {
                                depth--
                                if depth <= 0 {
                                        break
                                }
                        } else if tk.Val == "," && depth == 1 {
                                if j+1 < len(toks) && toks[j+1].Type == TokNumber {
                                        if d, err := strconv.ParseFloat(toks[j+1].Val, 64); err == nil {
                                                ts.DelayMS = d
                                        }
                                }
                                break
                        }
                }
        }
        fa.Timers = append(fa.Timers, ts)
}

// recordNetwork reads the first argument of a network call — toks[openIdx] is "(".
func (fa *FileAnalysis) recordNetwork(file string, line int, method string, toks []Token, openIdx int) {
        if openIdx+1 >= len(toks) {
                return
        }
        first := toks[openIdx+1]
        switch first.Type {
        case TokString:
                fa.recordNetworkURL(file, line, method, first.Str)
        case TokTemplate:
                if !strings.Contains(first.Str, "${") {
                        fa.recordNetworkURL(file, line, method, first.Str)
                } else {
                        fa.DynamicURLs = append(fa.DynamicURLs, CodeSite{File: file, Line: line, Kind: method + "(template)"})
                }
        default:
                fa.DynamicURLs = append(fa.DynamicURLs, CodeSite{File: file, Line: line, Kind: method + "(variable)"})
        }
}

func (fa *FileAnalysis) recordNetworkURL(file string, line int, method, u string) {
        fa.NetworkCalls = append(fa.NetworkCalls, NetworkSite{
                CodeSite: CodeSite{File: file, Line: line, Kind: method},
                Method:   method,
                URL:      u,
        })
}

// firstStringArg returns the first string argument of the call whose "(" is at
// openIdx.
func firstStringArg(toks []Token, openIdx int) string {
        return nthStringArg(toks, openIdx, 0)
}

// nthStringArg returns the nth string argument at depth 1 of the call.
func nthStringArg(toks []Token, openIdx int, n int) string {
        depth := 0
        seen := 0
        for j := openIdx; j < len(toks) && j < openIdx+200; j++ {
                tk := toks[j]
                if tk.Type == TokPunct {
                        if tk.Val == "(" || tk.Val == "[" || tk.Val == "{" {
                                depth++
                        } else if tk.Val == ")" || tk.Val == "]" || tk.Val == "}" {
                                depth--
                                if depth == 0 {
                                        return ""
                                }
                        }
                } else if depth == 1 && (tk.Type == TokString || tk.Type == TokTemplate) {
                        if seen == n {
                                return tk.Str
                        }
                        seen++
                }
        }
        return ""
}

// looksLikeURL: absolute or protocol-relative URL.
func looksLikeURL(s string) bool {
        return strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://") ||
                strings.HasPrefix(s, "ws://") || strings.HasPrefix(s, "wss://") ||
                strings.HasPrefix(s, "//")
}

// computeMetrics produces readability/obfuscation metrics (§36–38).
func computeMetrics(file string, src string, toks []Token) FileMetrics {
        m := FileMetrics{Bytes: len(src)}
        lines := strings.Split(src, "\n")
        m.Lines = len(lines)
        if m.Lines > 0 {
                m.AvgLineLen = float64(len(src)) / float64(m.Lines)
        }
        for _, l := range lines {
                if len(l) > m.MaxLineLen {
                        m.MaxLineLen = len(l)
                }
        }
        var identLens []int
        var stringEntropies []float64
        for _, t := range toks {
                switch t.Type {
                case TokIdent:
                        m.IdentCount++
                        identLens = append(identLens, len(t.Val))
                        if strings.HasPrefix(t.Val, "_0x") || (len(t.Val) <= 2 && strings.HasPrefix(t.Val, "_")) {
                                m.HexIdents++
                        }
                case TokKeyword:
                        if t.Val == "function" {
                                m.FunctionCount++
                        }
                case TokString, TokTemplate:
                        m.StringCount++
                        if len(t.Str) >= 40 {
                                m.LongStrings++
                                stringEntropies = append(stringEntropies, shannonEntropy(t.Str))
                                if looksBase64(t.Str) {
                                        m.Base64Blobs++
                                }
                                if strings.Contains(t.Val, `\x`) {
                                        m.BackslashX++
                                }
                        }
                }
        }
        if len(identLens) > 0 {
                sum := 0
                for _, l := range identLens {
                        sum += l
                }
                m.AvgIdentLen = float64(sum) / float64(len(identLens))
        }
        if len(stringEntropies) > 0 {
                sum := 0.0
                for _, e := range stringEntropies {
                        sum += e
                }
                m.AvgStringEntropy = sum / float64(len(stringEntropies))
        }
        if m.Bytes > 0 {
                m.SemicolonDensity = float64(strings.Count(src, ";")) / float64(m.Bytes) * 1000
        }
        return m
}

// CollectURLStrings gathers URL-bearing string literals (bare or in chains).
func CollectURLStrings(file string, src string) []CodeSite {
        var out []CodeSite
        toks := NewLexer(src).Lex()
        for _, t := range toks {
                if t.Type == TokString || t.Type == TokTemplate {
                        if looksLikeURL(t.Str) {
                                out = append(out, CodeSite{File: file, Line: t.Line, Kind: "literal", Arg: t.Str})
                        }
                }
        }
        return out
}
