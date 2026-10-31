package helper

import "os"

// ResetEnv replaces the environment with the one that every host command
// gets. Nothing comes from the login session, such as the TMPDIR of
// libpam-tmpdir, which a command as another user cannot write to.
func ResetEnv() {
	os.Clearenv()
	for _, kv := range [][2]string{
		// Modules read the output of host commands, so it must not be
		// translated.
		{"LC_ALL", "C.UTF-8"},
		{"PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"},
		{"HOME", "/root"},
		{"USER", "root"},
		{"LOGNAME", "root"},
	} {
		os.Setenv(kv[0], kv[1]) //nolint:errcheck // cannot fail for a valid name
	}
}
