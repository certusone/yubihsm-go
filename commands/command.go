package commands

import (
	"bytes"
	"encoding/binary"
)

type (
	CommandMessage struct {
		UUID        uint8
		CommandType CommandType
		SessionID   *uint8
		Data        []byte
		MAC         []byte
	}
)

func (c *CommandMessage) BodyLength() uint16 {
	length := len(c.Data)

	if c.MAC != nil {
		length += len(c.MAC)
	}

	if c.SessionID != nil {
		length += 1
	}

	return uint16(length)
}

func (c *CommandMessage) Serialize() ([]byte, error) {
	buffer := new(bytes.Buffer)

	// Write command type
	binary.Write(buffer, binary.BigEndian, c.CommandType)

	// Write length
	binary.Write(buffer, binary.BigEndian, uint16(c.BodyLength()))

	// Write sessionID
	if c.SessionID != nil {
		binary.Write(buffer, binary.BigEndian, *c.SessionID)
	}

	// Write data
	buffer.Write(c.Data)

	// Write MAC
	buffer.Write(c.MAC)

	return buffer.Bytes(), nil
}
