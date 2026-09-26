package main

// Local rule engine (§95). Rules are data, not scattered code: finding
// templates live in rules/rules.json, permission intelligence in
// rules/permissions.json, deprecated APIs in rules/apideprecations.json and
// dependency signatures in rules/depsignatures.json. All versioned together
// via RuleSetVersion (§125).

import (
	_ "embed"
	"encoding/json"
)

//go:embed rules/rules.json
var rulesJSON []byte

//go:embed rules/permissions.json
var permissionsJSON []byte

//go:embed rules/apideprecations.json
var apiDeprecationsJSON []byte

//go:embed rules/depsignatures.json
var depSignaturesJSON []byte

type Rule struct {
	ID             string `json:"id"`
	Category       string `json:"category"`
	Title          string `json:"title"`
	Summary        string `json:"summary"`
	WhyItMatters   string `json:"whyItMatters"`
	Recommendation string `json:"recommendation"`
	DefaultSeverity    string `json:"defaultSeverity"`
	DefaultConfidence  string `json:"defaultConfidence"`
}

type RuleSet struct {
	RuleSetVersion string          `json:"ruleSetVersion"`
	Rules          []Rule          `json:"rules"`
	index          map[string]Rule `json:"-"`
}

type PermissionMeta struct {
	Name        string `json:"name"`
	Risk        string `json:"risk"`
	Description string `json:"description"`
	TypicalUse  string `json:"typicalUse"`
	WhyItMatters string `json:"whyItMatters"`
}

type PermissionSet struct {
	Version     string                    `json:"version"`
	Permissions []PermissionMeta          `json:"permissions"`
	index       map[string]PermissionMeta `json:"-"`
}

type APIDeprecation struct {
	API           string `json:"api"`
	Status        string `json:"status"` // "removed" | "deprecated" | "legacy pattern"
	Note          string `json:"note"`
	Replacement   string `json:"replacement,omitempty"`
	AppliesTo     string `json:"appliesTo,omitempty"` // "mv2" | "mv3" | "all"
}

type APIDeprecationSet struct {
	Version     string           `json:"version"`
	Deprecations []APIDeprecation `json:"deprecations"`
	index       map[string]APIDeprecation `json:"-"`
}

type DepSignature struct {
	Library      string   `json:"library"`
	License      string   `json:"license,omitempty"`
	Signatures   []string `json:"signatures"`   // distinctive substrings (case-sensitive)
	FileHints    []string `json:"fileHints"`    // likely filenames
	VersionRegex string   `json:"versionRegex,omitempty"`
}

type DepSignatureSet struct {
	Version    string         `json:"version"`
	Signatures []DepSignature `json:"signatures"`
}

var ruleSet *RuleSet
var permissionSet *PermissionSet
var apiDepSet *APIDeprecationSet
var depSigSet *DepSignatureSet

func init() {
	if err := json.Unmarshal(rulesJSON, &ruleSet); err != nil {
		panic("embedded rules.json invalid: " + err.Error())
	}
	ruleSet.index = map[string]Rule{}
	for _, r := range ruleSet.Rules {
		ruleSet.index[r.ID] = r
	}

	if err := json.Unmarshal(permissionsJSON, &permissionSet); err != nil {
		panic("embedded permissions.json invalid: " + err.Error())
	}
	permissionSet.index = map[string]PermissionMeta{}
	for _, p := range permissionSet.Permissions {
		permissionSet.index[p.Name] = p
	}

	if err := json.Unmarshal(apiDeprecationsJSON, &apiDepSet); err != nil {
		panic("embedded apideprecations.json invalid: " + err.Error())
	}
	apiDepSet.index = map[string]APIDeprecation{}
	for _, d := range apiDepSet.Deprecations {
		apiDepSet.index[d.API] = d
	}

	if err := json.Unmarshal(depSignaturesJSON, &depSigSet); err != nil {
		panic("embedded depsignatures.json invalid: " + err.Error())
	}
}

// GetRule returns a rule by ID.
func GetRule(id string) Rule {
	if r, ok := ruleSet.index[id]; ok {
		return r
	}
	return Rule{ID: id, Category: "code quality", Title: id, DefaultSeverity: "informational", DefaultConfidence: "medium"}
}

// LookupPermission returns permission metadata (ok=false when unknown).
func LookupPermission(name string) (PermissionMeta, bool) {
	p, ok := permissionSet.index[name]
	return p, ok
}

// LookupAPIDeprecation returns deprecation metadata (ok=false when unknown).
func LookupAPIDeprecation(api string) (APIDeprecation, bool) {
	d, ok := apiDepSet.index[api]
	return d, ok
}

func DepSignatures() []DepSignature { return depSigSet.Signatures }
