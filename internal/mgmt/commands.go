package mgmt

import "fmt"

func ClientPendingAuth(cid, kid, url string, timeoutSeconds int) string {
	return fmt.Sprintf(`client-pending-auth %s %s "WEB_AUTH::%s" %d`, cid, kid, url, timeoutSeconds)
}

func ClientAuth(cid, kid string) string {
	return fmt.Sprintf("client-auth %s %s\nEND", cid, kid)
}

func ClientAuthNT(cid, kid string) string {
	return fmt.Sprintf("client-auth-nt %s %s", cid, kid)
}

func ClientDeny(cid, kid, reason string) string {
	if reason == "" {
		return fmt.Sprintf("client-deny %s %s", cid, kid)
	}
	return fmt.Sprintf(`client-deny %s %s "%s"`, cid, kid, reason)
}
