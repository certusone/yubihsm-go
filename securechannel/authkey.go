package securechannel

import (
	"crypto/sha256"
	"golang.org/x/crypto/pbkdf2"
)

type (
	// AuthKey is a key to authenticate with the HSM
	AuthKey []byte
)

const (
	authKeyLength     = 32
	authKeyIterations = 10000
	yubicoSeed        = "Yubico"
)

// deriveAuthKeyFromPwd derives an AuthKey using pkdf2 as specified in the HSM documentation
func deriveAuthKeyFromPwd(password string) AuthKey {
	return pbkdf2.Key([]byte(password), []byte(yubicoSeed), authKeyIterations, authKeyLength, sha256.New)
}

// GetEncKey returns the EncryptionKey part of the AuthKey
func (k AuthKey) GetEncKey() []byte {
	return k[:KeyLength]
}

// GetEncKey returns the MACKey part of the AuthKey
func (k AuthKey) GetMacKey() []byte {
	return k[KeyLength:]
}
