package mgmt

import (
	"bufio"
	"fmt"
	"strings"
)

func ParseHeader(line string) (EventType, string, string, error) {
	switch {
	case strings.HasPrefix(line, ">CLIENT:CONNECT,"):
		return parseCIDKID(EventConnect, strings.TrimPrefix(line, ">CLIENT:CONNECT,"))
	case strings.HasPrefix(line, ">CLIENT:REAUTH,"):
		return parseCIDKID(EventReauth, strings.TrimPrefix(line, ">CLIENT:REAUTH,"))
	case strings.HasPrefix(line, ">CLIENT:DISCONNECT,"):
		payload := strings.TrimPrefix(line, ">CLIENT:DISCONNECT,")
		cid := strings.TrimSpace(strings.SplitN(payload, ",", 2)[0])
		if cid == "" {
			return "", "", "", fmt.Errorf("disconnect missing cid")
		}
		return EventDisconnect, cid, "", nil
	case strings.HasPrefix(line, ">CLIENT:ESTABLISHED,"):
		payload := strings.TrimPrefix(line, ">CLIENT:ESTABLISHED,")
		cid := strings.TrimSpace(strings.SplitN(payload, ",", 2)[0])
		if cid == "" {
			return "", "", "", fmt.Errorf("established missing cid")
		}
		return EventEstablished, cid, "", nil
	case strings.HasPrefix(line, ">CLIENT:ADDRESS,"):
		// Single-line notification: >CLIENT:ADDRESS,{CID},{ADDR},{PRI}
		// No ENV block follows — ignore silently.
		return EventIgnored, "", "", nil
	case strings.HasPrefix(line, ">CLIENT:"):
		// Unknown future CLIENT notification — consume any ENV block that
		// may follow to keep the stream synchronized.
		return EventUnknown, "", "", nil
	default:
		return "", "", "", fmt.Errorf("unsupported event header: %s", line)
	}
}

type RawLogFunc func(line string)

func ReadEvent(scanner *bufio.Scanner, headerLine string) (Event, error) {
	return ReadEventWithRawLog(scanner, headerLine, nil)
}

func ReadEventWithRawLog(scanner *bufio.Scanner, headerLine string, rawLog RawLogFunc) (Event, error) {
	typ, cid, kid, err := ParseHeader(headerLine)
	if err != nil {
		return Event{}, err
	}
	event := Event{
		Type: typ,
		CID:  cid,
		KID:  kid,
		Env:  map[string]string{},
	}
	// Single-line events (ADDRESS) have no ENV block.
	if typ == EventIgnored {
		return event, nil
	}
	for scanner.Scan() {
		line := scanner.Text()
		if rawLog != nil {
			rawLog(line)
		}
		if line == ">CLIENT:ENV,END" {
			if event.Type == EventUnknown {
				event.Type = EventIgnored
			}
			return event, nil
		}
		if !strings.HasPrefix(line, ">CLIENT:ENV,") {
			continue
		}
		kv := strings.TrimPrefix(line, ">CLIENT:ENV,")
		idx := strings.IndexByte(kv, '=')
		if idx <= 0 {
			continue
		}
		event.Env[kv[:idx]] = kv[idx+1:]
	}
	if err := scanner.Err(); err != nil {
		return Event{}, err
	}
	return Event{}, fmt.Errorf("unexpected EOF waiting for >CLIENT:ENV,END")
}

func parseCIDKID(typ EventType, payload string) (EventType, string, string, error) {
	parts := strings.Split(payload, ",")
	if len(parts) < 2 {
		return "", "", "", fmt.Errorf("%s missing cid/kid", typ)
	}
	cid := strings.TrimSpace(parts[0])
	kid := strings.TrimSpace(parts[1])
	if cid == "" || kid == "" {
		return "", "", "", fmt.Errorf("%s missing cid/kid", typ)
	}
	return typ, cid, kid, nil
}
