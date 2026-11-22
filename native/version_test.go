package main

import "testing"

func TestParseBrowserVersion(t *testing.T) {
	cases := map[string]string{
		"Google Chrome 143.0.7489.125\n": "143.0.7489.125",
		"Chromium 131.0.6778.85":         "131.0.6778.85",
		"Google Chrome 143":              "143",
		"":                               "",
		"no version here":                "",
	}
	for in, want := range cases {
		if got := parseBrowserVersion(in); got != want {
			t.Errorf("parseBrowserVersion(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestOsVersionNonEmpty(t *testing.T) {
	if v := osVersion(); v == "" || v == "Not available" {
		t.Errorf("osVersion() = %q, want a real OS name", v)
	}
}

func TestEffectiveChromeVersionPrefersProvided(t *testing.T) {
	if got := effectiveChromeVersion("9.9.9"); got != "9.9.9" {
		t.Errorf("effectiveChromeVersion(9.9.9) = %q, want 9.9.9", got)
	}
	if got := effectiveChromeVersion(" "); got == "" {
		t.Error("effectiveChromeVersion(blank) must not be empty")
	}
}
