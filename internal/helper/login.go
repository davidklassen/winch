package helper

import "strconv"

// LoginUID returns the UID of the session's login user: SUDO_UID when sudo
// started the helper, else the helper's own UID.
func LoginUID(sudoUID string, uid int) uint32 {
	if id, err := strconv.ParseUint(sudoUID, 10, 32); err == nil {
		return uint32(id)
	}
	return uint32(uid)
}
