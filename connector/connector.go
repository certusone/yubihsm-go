package connector

import "github.com/loomnetwork/yubihsm-go/commands"

type (
	// Connector implements a simple request interface with a YubiHSM2
	Connector interface {
		// Request executes a command on the HSM and returns the binary response
		Request(command *commands.CommandMessage) ([]byte, error)
		// GetStatus requests the status of the HSM connector (not working for direct USB)
		GetStatus() (*StatusResponse, error)
	}

	// Status represents a status state of the HSM
	Status string

	// StatusResponse is the response to the GetStatus command containing information about the connector and HSM
	StatusResponse struct {
		Status  Status
		Serial  string
		Version string
		Pid     string
		Address string
		Port    string
	}
)
