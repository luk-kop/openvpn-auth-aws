package main

import "testing"

func TestVersionLine(t *testing.T) {
	oldVersion, oldRevision, oldBuildDate := version, revision, buildDate
	t.Cleanup(func() {
		version, revision, buildDate = oldVersion, oldRevision, oldBuildDate
	})

	version = "v1.2.3"
	revision = "abc1234"
	buildDate = "2026-05-13T12:00:00Z"

	got := versionLine()
	want := "v1.2.3 revision=abc1234 build_date=2026-05-13T12:00:00Z"
	if got != want {
		t.Fatalf("versionLine() = %q, want %q", got, want)
	}
}
