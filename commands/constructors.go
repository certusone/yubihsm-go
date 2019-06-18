package commands

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
)

func CreateCreateSessionCommand(keySetID uint16, hostChallenge []byte) (*CommandMessage, error) {
	command := &CommandMessage{
		CommandType: CommandTypeCreateSession,
	}

	payload := bytes.NewBuffer([]byte{})
	binary.Write(payload, binary.BigEndian, keySetID)
	payload.Write(hostChallenge)

	command.Data = payload.Bytes()

	return command, nil
}

func CreateAuthenticateSessionCommand(hostCryptogram []byte) (*CommandMessage, error) {
	command := &CommandMessage{
		CommandType: CommandTypeAuthenticateSession,
		Data:        hostCryptogram,
	}

	return command, nil
}

// Authenticated

func CreateResetCommand() (*CommandMessage, error) {
	command := &CommandMessage{
		CommandType: CommandTypeReset,
	}

	return command, nil
}

func CreateGenerateAsymmetricKeyCommand(keyID uint16, label []byte, domains uint16, capabilities uint64, algorithm Algorithm) (*CommandMessage, error) {
	if len(label) > LabelLength {
		return nil, errors.New("label is too long")
	}
	if len(label) < LabelLength {
		label = append(label, bytes.Repeat([]byte{0x00}, LabelLength-len(label))...)
	}

	command := &CommandMessage{
		CommandType: CommandTypeGenerateAsymmetricKey,
	}

	payload := bytes.NewBuffer([]byte{})
	binary.Write(payload, binary.BigEndian, keyID)
	payload.Write(label)
	binary.Write(payload, binary.BigEndian, domains)
	binary.Write(payload, binary.BigEndian, capabilities)
	binary.Write(payload, binary.BigEndian, algorithm)

	command.Data = payload.Bytes()

	return command, nil
}

func CreateSignDataEddsaCommand(keyID uint16, data []byte) (*CommandMessage, error) {
	command := &CommandMessage{
		CommandType: CommandTypeSignDataEddsa,
	}

	payload := bytes.NewBuffer([]byte{})
	binary.Write(payload, binary.BigEndian, keyID)
	payload.Write(data)

	command.Data = payload.Bytes()

	return command, nil
}

func CreateSignDataEcdsaCommand(keyID uint16, data []byte) (*CommandMessage, error) {
	command := &CommandMessage{
		CommandType: CommandTypeSignDataEcdsa,
	}

	payload := bytes.NewBuffer([]byte{})
	binary.Write(payload, binary.BigEndian, keyID)
	payload.Write(data)

	command.Data = payload.Bytes()

	return command, nil
}

func CreatePutAsymmetricKeyCommand(keyID uint16, label []byte, domains uint16, capabilities uint64, algorithm Algorithm, keyPart1 []byte, keyPart2 []byte) (*CommandMessage, error) {
	if len(label) > LabelLength {
		return nil, errors.New("label is too long")
	}
	if len(label) < LabelLength {
		label = append(label, bytes.Repeat([]byte{0x00}, LabelLength-len(label))...)
	}
	command := &CommandMessage{
		CommandType: CommandTypePutAsymmetric,
	}

	payload := bytes.NewBuffer([]byte{})
	binary.Write(payload, binary.BigEndian, keyID)
	payload.Write(label)
	binary.Write(payload, binary.BigEndian, domains)
	binary.Write(payload, binary.BigEndian, capabilities)
	binary.Write(payload, binary.BigEndian, algorithm)
	payload.Write(keyPart1)
	if keyPart2 != nil {
		payload.Write(keyPart2)
	}

	command.Data = payload.Bytes()

	return command, nil
}

type ListCommandOption func(w io.Writer)

func NewObjectTypeOption(objectType uint8) ListCommandOption {
	return func(w io.Writer) {
		binary.Write(w, binary.BigEndian, ListObjectParamType)
		binary.Write(w, binary.BigEndian, objectType)
	}
}

func NewIDOption(id uint16) ListCommandOption {
	return func(w io.Writer) {
		binary.Write(w, binary.BigEndian, ListObjectParamID)
		binary.Write(w, binary.BigEndian, id)
	}
}

func CreateListObjectsCommand(options ...ListCommandOption) (*CommandMessage, error) {
	command := &CommandMessage{
		CommandType: CommandTypeListObjects,
	}

	payload := bytes.NewBuffer([]byte{})
	for _, opt := range options {
		opt(payload)
	}

	command.Data = payload.Bytes()

	return command, nil
}

func CreateGetObjectInfoCommand(keyID uint16, objectType uint8) (*CommandMessage, error) {
	command := &CommandMessage{
		CommandType: CommandTypeGetObjectInfo,
	}

	payload := bytes.NewBuffer([]byte{})
	binary.Write(payload, binary.BigEndian, keyID)
	binary.Write(payload, binary.BigEndian, objectType)

	command.Data = payload.Bytes()

	return command, nil
}

func CreateCloseSessionCommand() (*CommandMessage, error) {
	command := &CommandMessage{
		CommandType: CommandTypeCloseSession,
	}

	return command, nil
}

func CreateGetPubKeyCommand(keyID uint16) (*CommandMessage, error) {
	command := &CommandMessage{
		CommandType: CommandTypeGetPubKey,
	}

	payload := bytes.NewBuffer([]byte{})
	binary.Write(payload, binary.BigEndian, keyID)
	command.Data = payload.Bytes()

	return command, nil
}

func CreateDeleteObjectCommand(objID uint16, objType uint8) (*CommandMessage, error) {
	command := &CommandMessage{
		CommandType: CommandTypeDeleteObject,
	}

	payload := bytes.NewBuffer([]byte{})
	binary.Write(payload, binary.BigEndian, objID)
	binary.Write(payload, binary.BigEndian, objType)
	command.Data = payload.Bytes()

	return command, nil
}

func CreateEchoCommand(data []byte) (*CommandMessage, error) {
	command := &CommandMessage{
		CommandType: CommandTypeEcho,
		Data:        data,
	}

	return command, nil
}
