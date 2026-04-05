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

func (e Event) CommonName() string {
	return e.Env["common_name"]
}

func (e Event) Username() string {
	return e.Env["username"]
}
