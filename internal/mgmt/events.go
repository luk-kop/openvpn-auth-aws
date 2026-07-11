package mgmt

import "time"

type EventType string

const (
	EventConnect     EventType = "CONNECT"
	EventReauth      EventType = "REAUTH"
	EventDisconnect  EventType = "DISCONNECT"
	EventEstablished EventType = "ESTABLISHED"
	EventIgnored     EventType = "IGNORED"
	EventUnknown     EventType = "UNKNOWN"
)

type Event struct {
	Type EventType
	CID  string
	KID  string
	Env  map[string]string
}

type EstablishedSession struct {
	CID         string
	CommonName  string
	ConnectedAt time.Time
}

// StatusClient is a neutral CLIENT_LIST record. Presence in CLIENT_LIST does
// not imply that OpenVPN has established the client.
type StatusClient struct {
	CID              string
	CommonName       string
	RealAddress      string
	VirtualAddress   string
	ConnectedAt      time.Time
	Established      bool
	RoutingConfirmed bool
}

type StatusSnapshot struct {
	Clients     []StatusClient
	Established []EstablishedSession
}

func (s StatusSnapshot) ClientByCID(cid string) (StatusClient, bool) {
	for _, client := range s.Clients {
		if client.CID == cid {
			return client, true
		}
	}
	return StatusClient{}, false
}

func (e Event) CommonName() string {
	return e.Env["common_name"]
}

func (e Event) Username() string {
	return e.Env["username"]
}
