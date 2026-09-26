package main

// JSON-RPC-style protocol between the Chrome extension and the native host
// (§155). Every request is validated; only whitelisted actions run (§102, §156).

import (
	"encoding/json"
	"fmt"
)

// ProtocolError carries the explicit error codes from §108.
type ProtocolError struct {
	Code    string
	Message string
}

func (e *ProtocolError) Error() string { return e.Code + ": " + e.Message }

type NativeRequest struct {
	RequestID string         `json:"requestId"`
	Action    string         `json:"action"`
	Options   map[string]any `json:"options,omitempty"`
}

type NativeResponse struct {
	RequestID string       `json:"requestId"`
	Success   bool         `json:"success"`
	Result    any          `json:"result,omitempty"`
	Error     *NativeError `json:"error,omitempty"`
	Event     string       `json:"event,omitempty"` // progress | extensionComplete
}

type NativeError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// allowedActions — §156 whitelist plus documented, narrowly scoped additions
// (see SECURITY.md). No generic execute/shell/run exists by design.
var allowedActions = map[string]bool{
	"getStatus":          true,
	"discoverProfiles":   true,
	"discoverExtensions": true,
	"scanExtension":      true,
	"scanAll":            true,
	"cancelScan":         true, // §88/§161 cancellation
	"getScan":            true,
	"getScanExtension":   true, // fetch one full extension report (1MB msg limit)
	"getSourceFile":      true, // §52 read-only source viewer
	"compareScans":       true,
	"exportReport":       true,
	"deleteHistory":      true,
	"getLMStudioStatus":  true, // §111/§112
	"testLMStudio":       true, // §111 Test Connection
	"askAuditor":         true, // §72 Ask the Auditor
	"scanArchive":        true, // §54 explicit user-selected CRX/ZIP
}

func validateRequest(raw []byte) (*NativeRequest, error) {
	var req NativeRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, &ProtocolError{Code: "SCAN_FAILED", Message: "malformed request JSON"}
	}
	if req.RequestID == "" {
		return nil, &ProtocolError{Code: "SCAN_FAILED", Message: "missing requestId"}
	}
	if req.Action == "" {
		return nil, &ProtocolError{Code: "SCAN_FAILED", Message: "missing action"}
	}
	if !allowedActions[req.Action] {
		return nil, &ProtocolError{Code: "ACCESS_DENIED", Message: fmt.Sprintf("unknown or rejected action: %s", req.Action)}
	}
	return &req, nil
}

func okResponse(id string, result any) NativeResponse {
	return NativeResponse{RequestID: id, Success: true, Result: result}
}

func errResponse(id string, e *ProtocolError) NativeResponse {
	return NativeResponse{RequestID: id, Success: false, Error: &NativeError{Code: e.Code, Message: e.Message}}
}

// progress event payloads (§88).
type ProgressEvent struct {
	Type    string `json:"type"`
	Stage   string `json:"stage"`
	Current int    `json:"current"`
	Total   int    `json:"total"`
	Message string `json:"message"`
}
