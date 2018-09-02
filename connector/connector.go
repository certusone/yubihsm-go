package connector

import "aiakos/commands"

type (
	Connector interface {
		Request(command *commands.CommandMessage) ([]byte, error)
		GetStatus() (*StatusResponse, error)
	}
)
