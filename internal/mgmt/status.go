package mgmt

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// ParseStatusLines parses one complete status 3 response, including END.
func ParseStatusLines(lines []string) (StatusSnapshot, error) {
	var parser statusParser
	for _, line := range lines {
		done, err := parser.consume(line)
		if err != nil {
			return StatusSnapshot{}, err
		}
		if done {
			return parser.snapshot, nil
		}
	}
	return StatusSnapshot{}, fmt.Errorf("status response missing END")
}

type statusParser struct {
	clientHeader map[string]int
	routeHeader  map[string]int
	clients      []StatusClient
	routes       []statusRoute
	snapshot     StatusSnapshot
	finalized    bool
}

type statusRoute struct {
	CommonName  string
	RealAddress string
}

func (p *statusParser) consume(line string) (bool, error) {
	if line == "END" {
		p.finalize()
		return true, nil
	}

	fields := splitStatusLine(line)
	if len(fields) == 0 {
		return false, nil
	}
	switch fields[0] {
	case "HEADER":
		if len(fields) < 3 {
			break
		}
		header := make(map[string]int, len(fields)-2)
		for i, name := range fields[2:] {
			header[normalizeHeader(name)] = i + 1 // data starts after record type
		}
		switch fields[1] {
		case "CLIENT_LIST":
			p.clientHeader = header
		case "ROUTING_TABLE":
			p.routeHeader = header
		}
	case "CLIENT_LIST":
		client, ok, err := p.parseClient(fields)
		if err != nil {
			return false, err
		}
		if ok {
			p.clients = append(p.clients, client)
		}
	case "ROUTING_TABLE":
		route, ok := p.parseRoute(fields)
		if ok {
			p.routes = append(p.routes, route)
		}
	}
	return false, nil
}

func (p *statusParser) parseClient(fields []string) (StatusClient, bool, error) {
	cid := statusValue(fields, p.clientHeader, "Client ID", "ClientID")
	cn := statusValue(fields, p.clientHeader, "Common Name", "CommonName")
	connected := statusValue(fields, p.clientHeader, "Connected Since (time_t)", "Connected Since", "ConnectedSince")
	if cid == "" || cn == "" || connected == "" {
		return StatusClient{}, false, nil
	}

	sec, err := strconv.ParseInt(connected, 10, 64)
	if err != nil {
		return StatusClient{}, false, fmt.Errorf("parse connected since %q: %w", connected, err)
	}
	return StatusClient{
		CID:            cid,
		CommonName:     cn,
		RealAddress:    statusValue(fields, p.clientHeader, "Real Address", "RealAddress"),
		VirtualAddress: statusValue(fields, p.clientHeader, "Virtual Address", "VirtualAddress"),
		ConnectedAt:    time.Unix(sec, 0),
	}, true, nil
}

func (p *statusParser) parseRoute(fields []string) (statusRoute, bool) {
	cn := statusValue(fields, p.routeHeader, "Common Name", "CommonName")
	realAddress := statusValue(fields, p.routeHeader, "Real Address", "RealAddress")
	if cn == "" || realAddress == "" {
		return statusRoute{}, false
	}
	return statusRoute{CommonName: cn, RealAddress: realAddress}, true
}

func (p *statusParser) finalize() {
	if p.finalized {
		return
	}
	p.finalized = true

	routes := make(map[string]struct{}, len(p.routes))
	for _, route := range p.routes {
		routes[route.CommonName+"\x00"+route.RealAddress] = struct{}{}
	}

	p.snapshot.Clients = make([]StatusClient, 0, len(p.clients))
	for _, client := range p.clients {
		_, client.RoutingConfirmed = routes[client.CommonName+"\x00"+client.RealAddress]
		client.Established = client.VirtualAddress != ""
		p.snapshot.Clients = append(p.snapshot.Clients, client)
		if client.Established {
			p.snapshot.Established = append(p.snapshot.Established, EstablishedSession{
				CID:         client.CID,
				CommonName:  client.CommonName,
				ConnectedAt: client.ConnectedAt,
			})
		}
	}
}

func statusValue(fields []string, header map[string]int, names ...string) string {
	for _, name := range names {
		if idx, ok := header[normalizeHeader(name)]; ok && idx < len(fields) {
			return fields[idx]
		}
	}
	return ""
}

func normalizeHeader(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.NewReplacer(" ", "", "_", "", "-", "", "(", "", ")", "").Replace(s)
	return s
}

func splitStatusLine(line string) []string {
	// OpenVPN management `status 3` output may be comma- or tab-separated
	// depending on the OpenVPN build/version.
	//
	// For tab-separated output we must preserve empty columns, because
	// CLIENT_LIST may omit virtual addresses and other fields, producing
	// consecutive tabs. Collapsing them shifts "Connected Since (time_t)" onto
	// the wrong field (for example "UNDEF").
	if strings.Contains(line, "\t") {
		return strings.Split(line, "\t")
	}
	return strings.Split(line, ",")
}
