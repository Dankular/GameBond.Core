// Package buildinfo carries the build id both sides report: the git commit the binary was
// built from. It is set at link time (-ldflags "-X github.com/Dankular/GameBond.Core/buildinfo.Commit=...");
// the server image gets it from the GIT_COMMIT build argument, so it is also the image tag.
package buildinfo

// Commit is the full git commit hash, or "dev" for an unstamped build.
var Commit = "dev"

// Short is the first 7 characters of Commit.
func Short() string {
	if len(Commit) > 7 {
		return Commit[:7]
	}
	return Commit
}
