package mgmt

import "fmt"

func ClientPendingAuth(cid, kid, url string, timeoutSeconds int) string {
	return fmt.Sprintf(`client-pending-auth %s %s "WEB_AUTH::%s" %d`, cid, kid, url, timeoutSeconds)
}

// ClientAuth returns the two lines that must be written sequentially:
// "client-auth {CID} {KID}" followed by "END".
func ClientAuth(cid, kid string) [2]string {
	return [2]string{
		fmt.Sprintf("client-auth %s %s", cid, kid),
		"END",
	}
}

func ClientAuthNT(cid, kid string) string {
	return fmt.Sprintf("client-auth-nt %s %s", cid, kid)
}

func ClientDeny(cid, kid, reason string) string {
	if reason == "" {
		reason = "denied"
	}
	return fmt.Sprintf(`client-deny %s %s "%s"`, cid, kid, reason)
}

func ClientKill(cid string) string {
	return fmt.Sprintf("client-kill %s", cid)
}
