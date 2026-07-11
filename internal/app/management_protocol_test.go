package app

import "testing"

func TestCommandContract(t *testing.T) {
	tests := []struct {
		command string
		want    responseContract
	}{
		{command: "status 3", want: multiLineUntilEnd},
		{command: "hold release", want: singleLineAck},
		{command: "client-auth 1 2\nEND", want: singleLineAck},
		{command: "client-auth-nt 1 2", want: singleLineAck},
		{command: "client-deny 1 2 reason", want: singleLineAck},
		{command: "client-pending-auth 1 2 WEB_AUTH::url 30", want: singleLineAck},
		{command: "client-kill 1 HALT", want: singleLineAck},
	}
	for _, tt := range tests {
		t.Run(tt.command, func(t *testing.T) {
			got, err := commandContract(tt.command)
			if err != nil {
				t.Fatalf("commandContract() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("commandContract() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCommandContractRejectsUnknownCommand(t *testing.T) {
	if _, err := commandContract("signal SIGTERM"); err == nil {
		t.Fatal("commandContract() accepted an unregistered command")
	}
}
