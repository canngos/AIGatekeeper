package main

import "testing"

func TestReadPasswordStripsBOMAndLineEnding(t *testing.T) {
	cases := map[string]string{
		"hunter2hunter2\r\n":       "hunter2hunter2",
		"hunter2hunter2\n":         "hunter2hunter2",
		"hunter2hunter2":           "hunter2hunter2",
		"\ufeffhunter2hunter2\r\n": "hunter2hunter2", // PowerShell prepends a BOM
		"\ufeffhunter2hunter2":     "hunter2hunter2",
		// A space inside or at the end of a password is deliberate.
		"two words here\r\n": "two words here",
		"trailing \n":        "trailing ",
	}
	for in, want := range cases {
		if got := readPassword(in); got != want {
			t.Errorf("readPassword(%q) = %q, want %q", in, got, want)
		}
	}
}
