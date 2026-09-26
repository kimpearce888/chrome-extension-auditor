package main

// Entry point. Two modes:
//  1. Native messaging host (default): length-prefixed JSON over stdio for
//     the Chrome extension (§102, §155).
//  2. CLI: --diagnose, --self-audit, --scan-dir, --export, --version — used
//     by Diagnose.bat, tests and power users.

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"sync"
)

func main() {
	diagnose := flag.Bool("diagnose", false, "run local diagnostics and exit")
	selfAudit := flag.String("self-audit", "", "audit the auditor itself at the given path (extension dist)")
	scanDir := flag.String("scan-dir", "", "scan a directory of extension packages (testing/diagnostics)")
	chromeUserData := flag.String("chrome-user-data", "", "override the Chrome User Data directory")
	scanMode := flag.String("mode", "standard", "scan mode: quick | standard | deep")
	outJSON := flag.String("json", "", "write scan result JSON to this path")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("Local Chrome Extension Auditor scanner %s (rules %s, analyzers %s)\n", ScannerVersion, ruleSet.RuleSetVersion, AnalyzerVersion)
		return
	}
	if *diagnose {
		RunDiagnostics()
		return
	}
	if *selfAudit != "" {
		RunSelfAudit(*selfAudit)
		return
	}
	if *scanDir != "" {
		RunDirScan(*scanDir, *chromeUserData, *scanMode, *outJSON)
		return
	}
	runNativeHost()
}

// ---- native messaging loop (§102, §155) ----

type Host struct {
	scanner *Scanner
	store   *Store
	outMu   sync.Mutex
	stdout  io.Writer
	inbox   chan NativeRequest // incoming requests (incl. cancel) while a scan runs
}

func runNativeHost() {
	store, err := OpenStore()
	if err != nil {
		// Still respond with errors over the protocol; never crash silently.
		store = &Store{Data: freshStore(), path: ""}
	}
	store.MarkInterruptedScans() // §160
	sc := NewScanner(store)
	host := &Host{
		scanner: sc,
		store:   store,
		stdout:  os.Stdout,
		inbox:   make(chan NativeRequest, 16),
	}

	go func() {
		reader := bufio.NewReaderSize(os.Stdin, 1<<20)
		for {
			msg, err := readNativeMessage(reader)
			if err != nil {
				// stdin closed (Chrome disconnected) -> clean shutdown
				close(host.inbox)
				return
			}
			req, verr := validateRequest(msg)
			if verr != nil {
				if pe, ok := verr.(*ProtocolError); ok {
					host.writeMessage(errResponse("", pe))
				} else {
					host.writeMessage(errResponse("", &ProtocolError{Code: "SCAN_FAILED", Message: verr.Error()}))
				}
				continue
			}
			if req.Action == "cancelScan" {
				sc.RequestCancel()
				host.writeMessage(okResponse(req.RequestID, map[string]any{"cancelled": true}))
				continue
			}
			select {
			case host.inbox <- *req:
			default:
				// busy: run inline
				host.handle(req)
			}
		}
	}()

	for req := range host.inbox {
		host.handle(&req)
	}
}

func (h *Host) handle(req *NativeRequest) {
	defer func() {
		if r := recover(); r != nil {
			h.writeMessage(errResponse(req.RequestID, &ProtocolError{Code: "SCAN_FAILED", Message: fmt.Sprintf("internal error: %v", r)}))
		}
	}()
	resp := h.dispatch(req)
	h.writeMessage(resp)
}

// readNativeMessage reads one Chrome native-messaging frame.
func readNativeMessage(r io.Reader) ([]byte, error) {
	var len uint32
	if err := binary.Read(r, binary.LittleEndian, &len); err != nil {
		return nil, err
	}
	if len == 0 || len > 64*1024*1024 {
		return nil, fmt.Errorf("invalid message length %d", len)
	}
	buf := make([]byte, len)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// writeMessage frames and writes a response (host->Chrome limit 1MB).
func (h *Host) writeMessage(resp NativeResponse) {
	data, err := json.Marshal(resp)
	if err != nil {
		return
	}
	if len(data) > 900_000 {
		// Oversized response: replace result with a paged pointer (§156
		// getScanExtension exists exactly for this).
		resp.Result = map[string]any{"error": "response too large", "hint": "use paged APIs"}
		data, _ = json.Marshal(resp)
	}
	h.outMu.Lock()
	defer h.outMu.Unlock()
	_ = binary.Write(os.Stdout, binary.LittleEndian, uint32(len(data)))
	_, _ = os.Stdout.Write(data)
}

// writeEvent sends a progress/notification event tied to a request id.
func (h *Host) writeEvent(requestID string, ev string, payload any) {
	h.writeMessage(NativeResponse{RequestID: requestID, Success: true, Event: ev, Result: payload})
}
