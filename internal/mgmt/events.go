package mgmt

type EventType string

const (
	EventConnect    EventType = "CONNECT"
	EventReauth     EventType = "REAUTH"
	EventDisconnect EventType = "DISCONNECT"
)

type Event struct {
	Type EventType
	CID  string
	KID  string
	Env  map[string]string
}

func (e Event) CommonName() string {
	return e.Env["common_name"]
}

func (e Event) Username() string {
	return e.Env["username"]
}
