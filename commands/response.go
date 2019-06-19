package commands

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

type (
	Response interface {
	}

	Error struct {
		Code ErrorCode
	}

	CreateSessionResponse struct {
		SessionID      uint8
		CardChallenge  []byte
		CardCryptogram []byte
	}

	SessionMessageResponse struct {
		SessionID     uint8
		EncryptedData []byte
		MAC           []byte
	}

	CreateAsymmetricKeyResponse struct {
		KeyID uint16
	}

	PutAsymmetricKeyResponse struct {
		KeyID uint16
	}

	ObjectInfoResponse struct {
		Capabilities         uint64
		ObjectID             uint16
		Length               uint16
		Domains              uint16
		Type                 uint8
		Algorithm            Algorithm
		Sequence             uint8
		Origin               uint8
		Label                [40]byte
		DelegatedCapabilites uint64
	}

	Object struct {
		ObjectID   uint16
		ObjectType uint8
		Sequence   uint8
	}

	ListObjectsResponse struct {
		Objects []Object
	}

	SignDataEddsaResponse struct {
		Signature []byte
	}

	SignDataEcdsaResponse struct {
		Signature []byte
	}

	GetPubKeyResponse struct {
		Algorithm Algorithm
		// KeyData can contain different formats depending on the algorithm according to the YubiHSM2 documentation.
		KeyData []byte
	}

	EchoResponse struct {
		Data []byte
	}
)

// ParseResponse parses the binary response from the card to the relevant Response type.
// If the response is an error zu parses the Error type response and returns an error of the
// type commands.Error with the parsed error message.
func ParseResponse(data []byte) (Response, error) {
	if len(data) < 3 {
		return nil, errors.New("invalid response")
	}

	transactionType := CommandType(data[0] + ResponseCommandOffset)

	var payloadLength uint16
	err := binary.Read(bytes.NewReader(data[1:3]), binary.BigEndian, &payloadLength)
	if err != nil {
		return nil, err
	}

	payload := data[3:]
	if len(payload) != int(payloadLength) {
		return nil, errors.New("response payload length does not equal the given length")
	}

	switch transactionType {
	case CommandTypeCreateSession:
		return parseCreateSessionResponse(payload)
	case CommandTypeAuthenticateSession:
		return nil, nil
	case CommandTypeSessionMessage:
		return parseSessionMessage(payload)
	case CommandTypeGenerateAsymmetricKey:
		return parseCreateAsymmetricKeyResponse(payload)
	case CommandTypeSignDataEddsa:
		return parseSignDataEddsaResponse(payload)
	case CommandTypeSignDataEcdsa:
		return parseSignDataEcdsaResponse(payload)
	case CommandTypePutAsymmetric:
		return parsePutAsymmetricKeyResponse(payload)
	case CommandTypeListObjects:
		return parseListObjectsResponse(payload)
	case CommandTypeGetObjectInfo:
		return parseGetObjectInfoResponse(payload)
	case CommandTypeCloseSession:
		return nil, nil
	case CommandTypeGetPubKey:
		return parseGetPubKeyResponse(payload)
	case CommandTypeDeleteObject:
		return nil, nil
	case CommandTypeEcho:
		return parseEchoResponse(payload)
	case ErrorResponseCode:
		return nil, parseErrorResponse(payload)
	default:
		return nil, errors.New("response type unknown / not implemented")
	}
}

func parseErrorResponse(payload []byte) error {
	if len(payload) != 1 {
		return errors.New("invalid response payload length")
	}

	return &Error{
		Code: ErrorCode(payload[0]),
	}
}

func parseSessionMessage(payload []byte) (Response, error) {
	return &SessionMessageResponse{
		SessionID:     payload[0],
		EncryptedData: payload[1 : len(payload)-8],
		MAC:           payload[len(payload)-8:],
	}, nil
}

func parseCreateSessionResponse(payload []byte) (Response, error) {
	if len(payload) != 17 {
		return nil, errors.New("invalid response payload length")
	}

	return &CreateSessionResponse{
		SessionID:      uint8(payload[0]),
		CardChallenge:  payload[1:9],
		CardCryptogram: payload[9:],
	}, nil
}

func parseCreateAsymmetricKeyResponse(payload []byte) (Response, error) {
	if len(payload) != 2 {
		return nil, errors.New("invalid response payload length")
	}

	var keyID uint16
	err := binary.Read(bytes.NewReader(payload[1:3]), binary.BigEndian, &keyID)
	if err != nil {
		return nil, err
	}

	return &CreateAsymmetricKeyResponse{
		KeyID: keyID,
	}, nil
}

func parseSignDataEddsaResponse(payload []byte) (Response, error) {
	return &SignDataEddsaResponse{
		Signature: payload,
	}, nil
}

func parseSignDataEcdsaResponse(payload []byte) (Response, error) {
	return &SignDataEcdsaResponse{
		Signature: payload,
	}, nil
}

func parsePutAsymmetricKeyResponse(payload []byte) (Response, error) {
	if len(payload) != 2 {
		return nil, errors.New("invalid response payload length")
	}

	var keyID uint16
	err := binary.Read(bytes.NewReader(payload), binary.BigEndian, &keyID)
	if err != nil {
		return nil, err
	}

	return &PutAsymmetricKeyResponse{
		KeyID: keyID,
	}, nil
}

func parseListObjectsResponse(payload []byte) (Response, error) {
	if len(payload)%4 != 0 {
		return nil, errors.New("invalid response payload length")
	}

	response := ListObjectsResponse{
		Objects: make([]Object, len(payload)/4),
	}

	err := binary.Read(bytes.NewReader(payload), binary.BigEndian, &response.Objects)
	if err != nil {
		return nil, err
	}

	return &response, nil
}

func parseGetObjectInfoResponse(payload []byte) (Response, error) {
	response := ObjectInfoResponse{}

	err := binary.Read(bytes.NewReader(payload), binary.BigEndian, &response)
	if err != nil {
		return nil, err
	}

	return &response, nil
}

func parseGetPubKeyResponse(payload []byte) (Response, error) {
	if len(payload) < 1 {
		return nil, errors.New("invalid response payload length")
	}
	return &GetPubKeyResponse{
		Algorithm: Algorithm(payload[0]),
		KeyData:   payload[1:],
	}, nil
}

func parseEchoResponse(payload []byte) (Response, error) {
	return &EchoResponse{
		Data: payload,
	}, nil
}

// Error formats a card error message into a human readable format
func (e *Error) Error() string {
	message := ""
	switch e.Code {
	case ErrorCodeOK:
		message = "OK"
	case ErrorCodeInvalidCommand:
		message = "Invalid command"
	case ErrorCodeInvalidData:
		message = "Invalid data"
	case ErrorCodeInvalidSession:
		message = "Invalid session"
	case ErrorCodeAuthFail:
		message = "Auth fail"
	case ErrorCodeSessionFull:
		message = "Session full"
	case ErrorCodeSessionFailed:
		message = "Session failed"
	case ErrorCodeStorageFailed:
		message = "Storage failed"
	case ErrorCodeWrongLength:
		message = "Wrong length"
	case ErrorCodeInvalidPermission:
		message = "Invalid permission"
	case ErrorCodeLogFull:
		message = "Log full"
	case ErrorCodeObjectNotFound:
		message = "Object not found"
	case ErrorCodeIDIllegal:
		message = "ID illegal"
	case ErrorCodeCommandUnexecuted:
		message = "Command unexecuted"
	default:
		message = "unknown"
	}

	return fmt.Sprintf("card responded with error: %s", message)
}
