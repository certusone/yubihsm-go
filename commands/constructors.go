package commands

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"

	"github.com/certusone/yubihsm-go/authkey"
)


func CreateDeviceInfoCommand() (*CommandMessage, error) {
	command := &CommandMessage{
		CommandType: CommandTypeDeviceInfo,
	}

	return command, nil
}

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

func CreateSignDataPkcs1Command(keyID uint16, data []byte) (*CommandMessage, error) {
	command := &CommandMessage{
		CommandType: CommandTypeSignDataPkcs1,
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

func NewDomainOption(domain uint16) ListCommandOption {
	return func(w io.Writer) {
		binary.Write(w, binary.BigEndian, ListObjectParamDomains)
		binary.Write(w, binary.BigEndian, domain)
	}
}

func NewLabelOption(label []byte) (ListCommandOption, error) {
	if len(label) > LabelLength {
		return nil, errors.New("label is too long")
	}
	if len(label) < LabelLength {
		label = append(label, bytes.Repeat([]byte{0x00}, LabelLength-len(label))...)
	}
	return func(w io.Writer) {
		binary.Write(w, binary.BigEndian, ListObjectParamLabel)
		binary.Write(w, binary.BigEndian, label)
	}, nil
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

func CreateDeriveEcdhCommand(objID uint16, pubkey []byte) (*CommandMessage, error) {
	command := &CommandMessage{
		CommandType: CommandTypeDeriveEcdh,
	}

	payload := bytes.NewBuffer([]byte{})
	binary.Write(payload, binary.BigEndian, objID)
	payload.Write(pubkey)
	command.Data = payload.Bytes()

	return command, nil
}

func CreateChangeAuthenticationKeyCommand(objID uint16, newPassword string) (*CommandMessage, error) {
	command := &CommandMessage{
		CommandType: CommandTypeChangeAuthenticationKey,
	}

	authKey := authkey.NewFromPassword(newPassword)
	payload := bytes.NewBuffer([]byte{})
	binary.Write(payload, binary.BigEndian, objID)
	binary.Write(payload, binary.BigEndian, AlgorithmYubicoAESAuthentication)
	payload.Write(authKey.GetEncKey())
	payload.Write(authKey.GetMacKey())
	command.Data = payload.Bytes()

	return command, nil
}

func CreatePutOpaqueCommand(objID uint16, label []byte, domains uint16, capabilities uint64, algorithm Algorithm, data []byte) (*CommandMessage, error) {
	if len(label) > LabelLength {
		return nil, errors.New("label is too long")
	}
	if len(label) < LabelLength {
		label = append(label, bytes.Repeat([]byte{0x00}, LabelLength-len(label))...)
	}

	command := &CommandMessage{
		CommandType: CommandTypePutOpaque,
	}

	payload := bytes.NewBuffer(nil)
	binary.Write(payload, binary.BigEndian, objID)
	payload.Write(label)
	binary.Write(payload, binary.BigEndian, domains)
	binary.Write(payload, binary.BigEndian, capabilities)
	binary.Write(payload, binary.BigEndian, algorithm)
	payload.Write(data)

	command.Data = payload.Bytes()

	return command, nil
}

func CreateGetOpaqueCommand(objID uint16) (*CommandMessage, error) {
	command := &CommandMessage{
		CommandType: CommandTypeGetOpaque,
	}

	payload := bytes.NewBuffer(nil)
	binary.Write(payload, binary.BigEndian, objID)
	command.Data = payload.Bytes()

	return command, nil
}

func CreateGetPseudoRandomCommand(numBytes uint16) *CommandMessage {
	command := &CommandMessage{
		CommandType: CommandTypeGetPseudoRandom,
	}

	payload := bytes.NewBuffer([]byte{})
	binary.Write(payload, binary.BigEndian, numBytes)
	command.Data = payload.Bytes()

	return command
}

func CreatePutWrapkeyCommand(objID uint16, label []byte, domains uint16, capabilities uint64, algorithm Algorithm, delegated uint64, wrapkey []byte) (*CommandMessage, error) {
	if len(label) > LabelLength {
		return nil, errors.New("label is too long")
	}
	if len(label) < LabelLength {
		label = append(label, bytes.Repeat([]byte{0x00}, LabelLength-len(label))...)
	}
	switch algorithm {
	case AlgorithmAES128CCMWrap:
		if keyLen := len(wrapkey); keyLen != 16 {
			return nil, errors.New("wrapkey is wrong length")
		}
	case AlgorithmAES192CCMWrap:
		if keyLen := len(wrapkey); keyLen != 24 {
			return nil, errors.New("wrapkey is wrong length")
		}
	case AlgorithmAES256CCMWrap:
		if keyLen := len(wrapkey); keyLen != 32 {
			return nil, errors.New("wrapkey is wrong length")
		}
	default:
		return nil, errors.New("invalid algorithm")
	}

	command := &CommandMessage{
		CommandType: CommandTypePutWrapKey,
	}

	payload := bytes.NewBuffer([]byte{})
	binary.Write(payload, binary.BigEndian, objID)
	payload.Write(label)
	binary.Write(payload, binary.BigEndian, domains)
	binary.Write(payload, binary.BigEndian, capabilities)
	binary.Write(payload, binary.BigEndian, algorithm)
	binary.Write(payload, binary.BigEndian, delegated)
	payload.Write(wrapkey)

	command.Data = payload.Bytes()

	return command, nil
}

func CreatePutAuthkeyCommand(objID uint16, label []byte, domains uint16, capabilities, delegated uint64, encKey, macKey []byte) (*CommandMessage, error) {
	if len(label) > LabelLength {
		return nil, errors.New("label is too long")
	}
	if len(label) < LabelLength {
		label = append(label, bytes.Repeat([]byte{0x00}, LabelLength-len(label))...)
	}
	algorithm := AlgorithmYubicoAESAuthentication
	// TODO: support P256 Authentication when it is released
	// https://github.com/Yubico/yubihsm-shell/blob/1c8e254603e72f3f39cf1c3910996dbfcdba2b12/lib/yubihsm.c#L3110
	if len(encKey) != 16 {
		return nil, errors.New("invalid encryption key length")
	}
	if len(macKey) != 16 {
		return nil, errors.New("invalid mac key length")
	}

	command := &CommandMessage{
		CommandType: CommandTypePutAuthKey,
	}

	payload := bytes.NewBuffer([]byte{})
	binary.Write(payload, binary.BigEndian, objID)
	payload.Write(label)
	binary.Write(payload, binary.BigEndian, domains)
	binary.Write(payload, binary.BigEndian, capabilities)
	binary.Write(payload, binary.BigEndian, algorithm)
	binary.Write(payload, binary.BigEndian, delegated)
	payload.Write(encKey)
	payload.Write(macKey)

	command.Data = payload.Bytes()

	return command, nil
}

func CreatePutDerivedAuthenticationKeyCommand(objID uint16, label []byte, domains uint16, capabilities uint64, delegated uint64, password string) (*CommandMessage, error) {
	authKey := authkey.NewFromPassword(password)
	return CreatePutAuthkeyCommand(objID, label, domains, capabilities, delegated, authKey.GetEncKey(), authKey.GetMacKey())
}

func CreateSignAttestationCertCommand(keyObjID, attestationObjID uint16) (*CommandMessage, error) {
	command := &CommandMessage{
		CommandType: CommandTypeAttestAsymmetric,
	}

	payload := bytes.NewBuffer([]byte{})
	binary.Write(payload, binary.BigEndian, keyObjID)
	binary.Write(payload, binary.BigEndian, attestationObjID)
	command.Data = payload.Bytes()

	return command, nil
}

func CreateExportWrappedCommand(wrapObjID uint16, objType uint8, objID uint16) (*CommandMessage, error) {
	command := &CommandMessage{
		CommandType: CommandTypeExportWrapped,
	}

	payload := bytes.NewBuffer([]byte{})
	binary.Write(payload, binary.BigEndian, wrapObjID)
	binary.Write(payload, binary.BigEndian, objType)
	binary.Write(payload, binary.BigEndian, objID)
	command.Data = payload.Bytes()

	return command, nil
}

// CreateImportWrappedCommand will import a wrapped/encrypted Object that was
// previously exported by an YubiHSM2 device. The imported object will retain
// its metadata (Object ID, Domains, Capabilities …etc), however, the object’s
// origin will be marked as imported instead of generated.
func CreateImportWrappedCommand(wrapObjID uint16, nonce, data []byte) (*CommandMessage, error) {
	command := &CommandMessage{
		CommandType: CommandTypeImportWrapped,
	}
	if len(nonce) != 13 {
		return nil, errors.New("invalid nonce length")
	}

	payload := bytes.NewBuffer([]byte{})
	binary.Write(payload, binary.BigEndian, wrapObjID)
	payload.Write(nonce)
	payload.Write(data)
	command.Data = payload.Bytes()

	return command, nil
}
