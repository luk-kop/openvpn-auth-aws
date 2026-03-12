package auth

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type StatePayload struct {
	SID string `json:"sid"`
	IP  string `json:"ip"`
	IAT int64  `json:"iat"`
	EXP int64  `json:"exp"`
}

func EncodeState(payload StatePayload, signer StateSigner) string {
	data, _ := json.Marshal(payload)
	encoded := base64.RawURLEncoding.EncodeToString(data)
	mac := signer.Sign(encoded)
	return encoded + "." + mac
}

func DecodeState(state string, signer StateSigner) (StatePayload, error) {
	parts := strings.SplitN(state, ".", 2)
	if len(parts) != 2 {
		return StatePayload{}, fmt.Errorf("invalid state format")
	}
	encoded, mac := parts[0], parts[1]

	if !signer.Verify(encoded, mac) {
		return StatePayload{}, fmt.Errorf("invalid state signature")
	}

	data, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return StatePayload{}, fmt.Errorf("decode state: %w", err)
	}

	var payload StatePayload
	if err := json.Unmarshal(data, &payload); err != nil {
		return StatePayload{}, fmt.Errorf("unmarshal state: %w", err)
	}

	if time.Now().Unix() > payload.EXP {
		return StatePayload{}, fmt.Errorf("state expired")
	}

	return payload, nil
}
