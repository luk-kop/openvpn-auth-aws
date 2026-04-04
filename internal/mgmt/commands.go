package mgmt

import (
	"fmt"
	"strings"
)

func ClientPendingAuth(cid, kid, url string, timeoutSeconds int) string {
	return fmt.Sprintf(`client-pending-auth %s %s "WEB_AUTH::%s" %d`, cid, kid, url, timeoutSeconds)
}

// ClientAuth returns the multi-line client-auth command as a single string
// so it can be sent atomically through the command channel. The caller
// writes it in one WriteLine call, preventing interleaving with other
// commands on the management socket.
func ClientAuth(cid, kid string) string {
	return fmt.Sprintf("client-auth %s %s\nEND", cid, kid)
}

func ClientAuthNT(cid, kid string) string {
	return fmt.Sprintf("client-auth-nt %s %s", cid, kid)
}

func ClientDeny(cid, kid, reason string) string {
	if reason == "" {
		reason = "denied"
	}
	reason = strings.NewReplacer(`\`, `\\`, `"`, `'`).Replace(reason)
	return fmt.Sprintf(`client-deny %s %s "%s"`, cid, kid, reason)
}

func ClientKill(cid string) string {
	return fmt.Sprintf("client-kill %s", cid)
}
