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

	DeviceInfoResponse struct {
		MajorVersion  uint8
		MinorVersion  uint8
		BuildVersion  uint8
		SerialNumber  uint32
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

	SignDataPkcs1Response struct {
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

	DeriveEcdhResponse struct {
		XCoordinate []byte
	}

	ChangeAuthenticationKeyResponse struct {
		ObjectID uint16
	}

	PutWrapkeyResponse struct {
		ObjectID uint16
	}

	PutAuthkeyResponse struct {
		ObjectID uint16
	}

	PutOpaqueResponse struct {
		ObjectID uint16
	}

	GetOpaqueResponse struct {
		Data []byte
	}

	SignAttestationCertResponse struct {
		Cert []byte
	}

	ExportWrappedResponse struct {
		Nonce []byte
		Data  []byte
	}

	ImportWrappedResponse struct {
		ObjectType uint8
		ObjectID   uint16
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
	case CommandTypeDeviceInfo:
		return parseDeviceInfoResponse(payload)
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
	case CommandTypeSignDataPkcs1:
		return parseSignDataPkcs1Response(payload)
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
	case CommandTypeDeriveEcdh:
		return parseDeriveEcdhResponse(payload)
	case CommandTypeChangeAuthenticationKey:
		return parseChangeAuthenticationKeyResponse(payload)
	case CommandTypeGetPseudoRandom:
		return parseGetPseudoRandomResponse(payload), nil
	case CommandTypePutWrapKey:
		return parsePutWrapkeyResponse(payload)
	case CommandTypePutAuthKey:
		return parsePutAuthkeyResponse(payload)
	case CommandTypePutOpaque:
		return parsePutOpaqueResponse(payload)
	case CommandTypeGetOpaque:
		return parseGetOpaqueResponse(payload)
	case CommandTypeAttestAsymmetric:
		return parseAttestationCertResponse(payload)
	case CommandTypeExportWrapped:
		return parseExportWrappedResponse(payload)
	case CommandTypeImportWrapped:
		return parseImportWrappedResponse(payload)
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

func parseDeviceInfoResponse(payload []byte) (Response, error) {
	var serialNumber uint32
	err := binary.Read(bytes.NewReader(payload[3:7]), binary.BigEndian, &serialNumber)
	if err != nil {
		return nil, err
	}

	return &DeviceInfoResponse{
		MajorVersion: payload[0],
		MinorVersion: payload[1],
		BuildVersion: payload[2],
		SerialNumber: serialNumber,
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

func parseSignDataPkcs1Response(payload []byte) (Response, error) {
	if len(payload) < 1 {
		return nil, errors.New("invalid response payload length")
	}

	return &SignDataPkcs1Response{
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

func parseDeriveEcdhResponse(payload []byte) (Response, error) {
	return &DeriveEcdhResponse{
		XCoordinate: payload,
	}, nil
}

func parseChangeAuthenticationKeyResponse(payload []byte) (Response, error) {
	if len(payload) != 2 {
		return nil, errors.New("invalid response payload length")
	}

	var objectID uint16
	err := binary.Read(bytes.NewReader(payload), binary.BigEndian, &objectID)
	if err != nil {
		return nil, err
	}

	return &ChangeAuthenticationKeyResponse{ObjectID: objectID}, nil
}

func parseGetPseudoRandomResponse(payload []byte) Response {
	return payload
}

func parsePutWrapkeyResponse(payload []byte) (Response, error) {
	if len(payload) != 2 {
		return nil, errors.New("invalid response payload length")
	}

	var objectID uint16
	err := binary.Read(bytes.NewReader(payload), binary.BigEndian, &objectID)
	if err != nil {
		return nil, err
	}
	return &PutWrapkeyResponse{ObjectID: objectID}, nil
}

func parsePutAuthkeyResponse(payload []byte) (Response, error) {
	if len(payload) != 2 {
		return nil, errors.New("invalid response payload length")
	}

	var objectID uint16
	err := binary.Read(bytes.NewReader(payload), binary.BigEndian, &objectID)
	if err != nil {
		return nil, err
	}

	return &PutAuthkeyResponse{ObjectID: objectID}, nil
}

func parsePutOpaqueResponse(payload []byte) (Response, error) {
	if len(payload) != 2 {
		return nil, errors.New("invalid response payload length")
	}

	var objectID uint16
	err := binary.Read(bytes.NewReader(payload), binary.BigEndian, &objectID)
	if err != nil {
		return nil, err
	}

	return &PutOpaqueResponse{
		ObjectID: objectID,
	}, nil
}

func parseGetOpaqueResponse(payload []byte) (Response, error) {
	if len(payload) < 1 {
		return nil, errors.New("invalid response payload length")
	}

	return &GetOpaqueResponse{
		Data: payload,
	}, nil
}

func parseAttestationCertResponse(payload []byte) (Response, error) {
	if len(payload) < 1 {
		return nil, errors.New("invalid response payload length")
	}

	return &SignAttestationCertResponse{
		Cert: payload,
	}, nil
}

func parseExportWrappedResponse(payload []byte) (Response, error) {
	if len(payload) < 13 {
		return nil, errors.New("invalid response payload length")
	}

	return &ExportWrappedResponse{
		Nonce: payload[:13],
		Data:  payload[13:],
	}, nil
}

func parseImportWrappedResponse(payload []byte) (Response, error) {
	if len(payload) != 3 {
		return nil, errors.New("invalid response payload length")
	}

	var objID uint16
	err := binary.Read(bytes.NewReader(payload[1:3]), binary.BigEndian, &objID)
	if err != nil {
		return nil, err
	}

	return &ImportWrappedResponse{
		ObjectType: uint8(payload[0]),
		ObjectID:   objID,
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
	case ErrorCodeInvalidID:
		message = "Invalid ID"
	case ErrorCodeCommandUnexecuted:
		message = "Command unexecuted"
	case ErrorCodeSSHCAConstraintViolation:
		message = "SSH CA constraint violation"
	case ErrorCodeInvalidOTP:
		message = "Invalid OTP"
	case ErrorCodeDemoMode:
		message = "Demo mode"
	case ErrorCodeObjectExists:
		message = "Object exists"
	default:
		message = "Unknown"
	}

	return fmt.Sprintf("card responded with error: %s", message)
}
