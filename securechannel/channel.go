package securechannel

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"sync"

	"github.com/enceve/crypto/cmac"
	"github.com/loomnetwork/yubihsm-go/commands"
	"github.com/loomnetwork/yubihsm-go/connector"
)

type (
	// SecureChannel implements a communication channel with a YubiHSM2 as specified in the SCP03 standard
	SecureChannel struct {
		// connector is used to communicate with the card
		connector connector.Connector
		// authKeySlot is the slot of the used authKey on the HSM
		authKeySlot uint16
		// keyChain holds the keys generated in the authentication ceremony
		keyChain *KeyChain
		// channelLock is used to lock encrypted communications to prevent race conditions
		channelLock sync.Mutex

		// ID is the ID of the session with the HSM
		ID uint8
		// Counter of commands performed on the session
		Counter uint32
		// SecurityLevel is the authentication state of the session
		SecurityLevel SecurityLevel

		// HostChallenge is the auth challenge of the host
		HostChallenge []byte
		// DeviceChallenge is the auth challenge of the device
		DeviceChallenge []byte

		// AuthKey to authenticate against the HSM; must match authKeySlot
		AuthKey AuthKey

		// MACChainValue is the last MAC to allow MAC chaining
		MACChainValue []byte
	}

	// KeyDerivationConstant used to derive keys using KDF
	KeyDerivationConstant byte

	// SecurityLevel indicates an auth state of a session/channel
	SecurityLevel byte

	// KeyChain holds session keys
	KeyChain struct {
		EncKey  []byte
		MACKey  []byte
		RMACKey []byte
	}

	// MessageType indicates whether a message is a command or response
	MessageType byte
)

const (
	MACLength        = 8
	ChallengeLength  = 8
	CryptogramLength = 8
	KeyLength        = 16

	DerivationConstantEncKey  KeyDerivationConstant = 0x04
	DerivationConstantMACKey  KeyDerivationConstant = 0x06
	DerivationConstantRMACKey KeyDerivationConstant = 0x07

	DerivationConstantDeviceCryptogram KeyDerivationConstant = 0x00
	DerivationConstantHostCryptogram   KeyDerivationConstant = 0x01

	SecurityLevelUnauthenticated SecurityLevel = 0
	SecurityLevelAuthenticated   SecurityLevel = 1

	MessageTypeCommand  MessageType = 0
	MessageTypeResponse MessageType = 1

	MaxMessagesPerSession = 10000
)

// NewSecureChannel initiates a new secure channel to communicate with an HSM using the given authKey
// Call Authenticate next to establish a session.
func NewSecureChannel(connector connector.Connector, authKeySlot uint16, password string) (*SecureChannel, error) {
	channel := &SecureChannel{
		ID:            0,
		AuthKey:       deriveAuthKeyFromPwd(password),
		MACChainValue: make([]byte, 16),
		SecurityLevel: SecurityLevelUnauthenticated,
		authKeySlot:   authKeySlot,
		connector:     connector,
	}

	hostChallenge := make([]byte, 8)
	_, err := rand.Read(hostChallenge)
	if err != nil {
		return nil, err
	}
	channel.HostChallenge = hostChallenge

	return channel, nil
}

// Authenticate establishes an authenticated session with the HSM
func (s *SecureChannel) Authenticate() error {
	if s.SecurityLevel != SecurityLevelUnauthenticated {
		return errors.New("the session is already authenticated")
	}

	s.channelLock.Lock()
	defer s.channelLock.Unlock()

	command, _ := commands.CreateCreateSessionCommand(s.authKeySlot, s.HostChallenge)
	response, err := s.SendCommand(command)
	if err != nil {
		return err
	}

	createSessionResp, match := response.(*commands.CreateSessionResponse)
	if !match {
		return errors.New("invalid response type")
	}

	s.ID = createSessionResp.SessionID
	s.DeviceChallenge = createSessionResp.CardChallenge

	// Update keychain
	err = s.updateKeychain()
	if err != nil {
		return err
	}

	// Validate device cryptogram
	deviceCryptogram, err := s.deriveKDF(s.keyChain.MACKey, DerivationConstantDeviceCryptogram, CryptogramLength)
	if err != nil {
		return err
	}

	if !bytes.Equal(deviceCryptogram, createSessionResp.CardCryptogram) {
		return errors.New("authentication failed: device sent wrong cryptogram")
	}

	// Create host cryptogram
	hostCryptogram, err := s.deriveKDF(s.keyChain.MACKey, DerivationConstantHostCryptogram, CryptogramLength)
	if err != nil {
		return err
	}

	// Authenticate session
	authenticateCommand, err := commands.CreateAuthenticateSessionCommand(hostCryptogram)
	if err != nil {
		return err
	}
	_, err = s.sendMACCommand(authenticateCommand)
	if err != nil {
		return err
	}

	// Set counter to 1 as specified by the protocol
	s.Counter = 1

	s.SecurityLevel = SecurityLevelAuthenticated

	return nil
}

// SendCommand sends an unauthenticated command to the HSM and returns the parsed response
func (s *SecureChannel) SendCommand(c *commands.CommandMessage) (commands.Response, error) {
	resp, err := s.connector.Request(c)
	if err != nil {
		return nil, err
	}

	return commands.ParseResponse(resp)
}

// SendEncryptedCommand sends an encrypted & authenticated command to the HSM
// and returns the decrypted and parsed response.
func (s *SecureChannel) SendEncryptedCommand(c *commands.CommandMessage) (commands.Response, error) {
	if s.SecurityLevel != SecurityLevelAuthenticated {
		return nil, errors.New("the session is not authenticated")
	}

	if s.Counter >= MaxMessagesPerSession {
		return nil, errors.New("channel has reached its message limit; please recreate")
	}

	// Lock the encrypted channel
	s.channelLock.Lock()
	defer s.channelLock.Unlock()

	// Create the cipher using the session encryption key
	block, err := aes.NewCipher(s.keyChain.EncKey)
	if err != nil {
		return nil, err
	}

	// Pad the counter by 12 bytes
	icv := new(bytes.Buffer)
	icv.Write(bytes.Repeat([]byte{0}, 12))
	binary.Write(icv, binary.BigEndian, s.Counter)

	// Encrypt the padded counter to generate the IV
	iv := make([]byte, KeyLength)
	block.Encrypt(iv, icv.Bytes())

	// Setup the CBC encrypter
	encrypter := cipher.NewCBCEncrypter(block, iv)

	// Serialize and encrypt the wrapped command
	commandData, _ := c.Serialize()
	encryptedCommand := make([]byte, len(pad(commandData)))
	encrypter.CryptBlocks(encryptedCommand, pad(commandData))

	// Send the wrapped command in a SessionMessage
	resp, err := s.sendMACCommand(&commands.CommandMessage{
		CommandType: commands.CommandTypeSessionMessage,
		Data:        encryptedCommand,
	})
	if err != nil {
		return nil, err
	}

	// Cast and check the response
	sessionMessage, match := resp.(*commands.SessionMessageResponse)
	if !match {
		return nil, errors.New("invalid response type")
	}

	// Verify MAC
	expectedMac, err := s.calculateMAC(&commands.CommandMessage{
		CommandType: commands.CommandTypeSessionMessage + commands.ResponseCommandOffset,
		SessionID:   &sessionMessage.SessionID,
		Data:        sessionMessage.EncryptedData,
	}, MessageTypeResponse)

	if !bytes.Equal(expectedMac[:MACLength], sessionMessage.MAC) {
		return nil, errors.New("invalid response MAC")
	}

	// Update session state
	s.Counter++

	// Init the CBC decrypter
	decrypter := cipher.NewCBCDecrypter(block, iv)

	// Decrypt the wrapped response
	decryptedResponse := make([]byte, len(sessionMessage.EncryptedData))
	decrypter.CryptBlocks(decryptedResponse, sessionMessage.EncryptedData)

	// Parse and return the wrapped response
	return commands.ParseResponse(unpad(decryptedResponse))
}

func (s *SecureChannel) Close() error {
	command, err := commands.CreateCloseSessionCommand()
	if err != nil {
		return err
	}

	_, err = s.SendEncryptedCommand(command)
	if err != nil {
		return err
	}

	return nil
}

// sendMACCommand sends a MAC authenticated command to the HSM and returns a parsed response
func (s *SecureChannel) sendMACCommand(c *commands.CommandMessage) (commands.Response, error) {

	// Set command sessionID to this session
	c.SessionID = &s.ID

	// Calculate MAC for the command
	sum, err := s.calculateMAC(c, MessageTypeCommand)
	if err != nil {
		return nil, err
	}

	// Update chain value
	s.MACChainValue = sum

	// Set command MAC to calculated mac
	c.MAC = sum[:MACLength]

	return s.SendCommand(c)
}

// calculateMAC calculates the authenticated MAC for a command or response.
// This is stateful since it uses the MACChainValue.
func (s *SecureChannel) calculateMAC(c *commands.CommandMessage, messageType MessageType) ([]byte, error) {

	// Select the right key
	var key []byte
	switch messageType {
	case MessageTypeCommand:
		key = s.keyChain.MACKey
	case MessageTypeResponse:
		key = s.keyChain.RMACKey
	default:
		return nil, errors.New("invalid messageType")
	}

	// Setup CMAC using aes
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	mac, err := cmac.New(block)
	if err != nil {
		return nil, err
	}

	// Setup a buffer for the cmac data
	buffer := new(bytes.Buffer)

	// Write the MacChainValue
	buffer.Write(s.MACChainValue)

	// Write command type
	binary.Write(buffer, binary.BigEndian, c.CommandType)

	// Write length
	binary.Write(buffer, binary.BigEndian, uint16(1+len(c.Data)+MACLength))

	// Write sessionID
	binary.Write(buffer, binary.BigEndian, c.SessionID)

	// Write data
	buffer.Write(c.Data)

	// Write buffer to MAC
	mac.Write(buffer.Bytes())

	return mac.Sum([]byte{}), nil
}

// updateKeychain derives and stores the session keys.
func (s *SecureChannel) updateKeychain() error {
	keyChain := &KeyChain{}

	encKey, err := s.deriveKDF(s.AuthKey.GetEncKey(), DerivationConstantEncKey, KeyLength)
	if err != nil {
		return err
	}
	keyChain.EncKey = encKey

	macKey, err := s.deriveKDF(s.AuthKey.GetMacKey(), DerivationConstantMACKey, KeyLength)
	if err != nil {
		return err
	}
	keyChain.MACKey = macKey

	rmacKey, err := s.deriveKDF(s.AuthKey.GetMacKey(), DerivationConstantRMACKey, KeyLength)
	if err != nil {
		return err
	}
	keyChain.RMACKey = rmacKey

	s.keyChain = keyChain
	return nil
}

// deriveKDF derives a key using SCP03's KDF.
// derivationConstant and keyLen define which key to derive.
func (s *SecureChannel) deriveKDF(key []byte, derivationConstant KeyDerivationConstant, keyLen uint8) ([]byte, error) {
	if len(key) != KeyLength {
		return nil, errors.New("invalid macKey length; should be 16")
	}

	if len(s.HostChallenge) != ChallengeLength {
		return nil, errors.New("invalid HostChallenge length; should be 8")
	}

	if len(s.DeviceChallenge) != ChallengeLength {
		return nil, errors.New("invalid DeviceChallenge length; should be 8")
	}

	derivationData := new(bytes.Buffer)
	derivationData.Write([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, byte(derivationConstant)})

	derivationData.WriteByte(0x00)

	binary.Write(derivationData, binary.BigEndian, uint16(keyLen*8))

	derivationData.WriteByte(0x01)
	derivationData.Write(s.HostChallenge)
	derivationData.Write(s.DeviceChallenge)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	mac, err := cmac.New(block)
	if err != nil {
		return nil, err
	}

	mac.Write(derivationData.Bytes())
	kdf := mac.Sum([]byte{})

	return kdf[:keyLen], nil
}
