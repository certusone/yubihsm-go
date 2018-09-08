package connector

import "github.com/certusone/aiakos/commands"

type (
	Connector interface {
		Request(command *commands.CommandMessage) ([]byte, error)
		GetStatus() (*StatusResponse, error)
	}
)
