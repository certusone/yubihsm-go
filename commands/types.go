package commands

type (
	CommandType uint8
	ErrorCode   uint8
	Algorithm   uint8
)

const (
	ResponseCommandOffset = 0x80
	ErrorResponseCode     = 0xff

	// LabelLength is the max length of a label
	LabelLength = 40

	CommandTypeEcho                  CommandType = 0x01
	CommandTypeCreateSession         CommandType = 0x03
	CommandTypeAuthenticateSession   CommandType = 0x04
	CommandTypeSessionMessage        CommandType = 0x05
	CommandTypeDeviceInfo            CommandType = 0x06
	CommandTypeReset                 CommandType = 0x08
	CommandTypeCloseSession          CommandType = 0x40
	CommandTypeStorageStatus         CommandType = 0x41
	CommandTypePutOpaque             CommandType = 0x42
	CommandTypeGetOpaque             CommandType = 0x43
	CommandTypePutAuthKey            CommandType = 0x44
	CommandTypePutAsymmetric         CommandType = 0x45
	CommandTypeGenerateAsymmetricKey CommandType = 0x46
	CommandTypeSignDataPkcs1         CommandType = 0x47
	CommandTypeListObjects           CommandType = 0x48
	CommandTypeDecryptPkcs1          CommandType = 0x49
	CommandTypeExportWrapped         CommandType = 0x4a
	CommandTypeImportWrapped         CommandType = 0x4b
	CommandTypePutWrapKey            CommandType = 0x4c
	CommandTypeGetLogs               CommandType = 0x4d
	CommandTypeGetObjectInfo         CommandType = 0x4e
	CommandTypePutOption             CommandType = 0x4f
	CommandTypeGetOption             CommandType = 0x50
	CommandTypeGetPseudoRandom       CommandType = 0x51
	CommandTypePutHMACKey            CommandType = 0x52
	CommandTypeHMACData              CommandType = 0x53
	CommandTypeGetPubKey             CommandType = 0x54
	CommandTypeSignDataPss           CommandType = 0x55
	CommandTypeSignDataEcdsa         CommandType = 0x56
	CommandTypeDecryptEcdh           CommandType = 0x57
	CommandTypeDeleteObject          CommandType = 0x58
	CommandTypeDecryptOaep           CommandType = 0x59
	CommandTypeGenerateHMACKey       CommandType = 0x5a
	CommandTypeGenerateWrapKey       CommandType = 0x5b
	CommandTypeVerifyHMAC            CommandType = 0x5c
	CommandTypeOTPDecrypt            CommandType = 0x60
	CommandTypeOTPAeadCreate         CommandType = 0x61
	CommandTypeOTPAeadRandom         CommandType = 0x62
	CommandTypeOTPAeadRewrap         CommandType = 0x63
	CommandTypeAttestAsymmetric      CommandType = 0x64
	CommandTypePutOTPAeadKey         CommandType = 0x65
	CommandTypeGenerateOTPAeadKey    CommandType = 0x66
	CommandTypeSetLogIndex           CommandType = 0x67
	CommandTypeWrapData              CommandType = 0x68
	CommandTypeUnwrapData            CommandType = 0x69
	CommandTypeSignDataEddsa         CommandType = 0x6a
	CommandTypeSetBlink              CommandType = 0x6b

	// Errors
	ErrorCodeOK                ErrorCode = 0x00
	ErrorCodeInvalidCommand    ErrorCode = 0x01
	ErrorCodeInvalidData       ErrorCode = 0x02
	ErrorCodeInvalidSession    ErrorCode = 0x03
	ErrorCodeAuthFail          ErrorCode = 0x04
	ErrorCodeSessionFull       ErrorCode = 0x05
	ErrorCodeSessionFailed     ErrorCode = 0x06
	ErrorCodeStorageFailed     ErrorCode = 0x07
	ErrorCodeWrongLength       ErrorCode = 0x08
	ErrorCodeInvalidPermission ErrorCode = 0x09
	ErrorCodeLogFull           ErrorCode = 0x0a
	ErrorCodeObjectNotFound    ErrorCode = 0x0b
	ErrorCodeIDIllegal         ErrorCode = 0x0c
	ErrorCodeCommandUnexecuted ErrorCode = 0xff

	// Algorithms
	AlgorithmP256      Algorithm = 12
	AlgorithmSecp256k1 Algorithm = 15
	AlgorighmED25519   Algorithm = 46

	// Capabilities
	CapabilityGetOpaque             uint64 = 0x0000000000000001
	CapabilityPutOpaque             uint64 = 0x0000000000000002
	CapabilityPutAuthKey            uint64 = 0x0000000000000004
	CapabilityPutAsymmetric         uint64 = 0x0000000000000008
	CapabilityAsymmetricGen         uint64 = 0x0000000000000010
	CapabilityAsymmetricSignPkcs    uint64 = 0x0000000000000020
	CapabilityAsymmetricSignPss     uint64 = 0x0000000000000040
	CapabilityAsymmetricSignEcdsa   uint64 = 0x0000000000000080
	CapabilityAsymmetricSignEddsa   uint64 = 0x0000000000000100
	CapabilityAsymmetricDecryptPkcs uint64 = 0x0000000000000200
	CapabilityAsymmetricDecryptOaep uint64 = 0x0000000000000400
	CapabilityAsymmetricDecryptEcdh uint64 = 0x0000000000000800
	CapabilityExportWrapped         uint64 = 0x0000000000001000
	CapabilityImportWrapped         uint64 = 0x0000000000002000
	CapabilityPutWrapKey            uint64 = 0x0000000000004000
	CapabilityGenerateWrapKey       uint64 = 0x0000000000008000
	CapabilityExportUnderWrap       uint64 = 0x0000000000010000
	CapabilityPutOption             uint64 = 0x0000000000020000
	CapabilityGetOption             uint64 = 0x0000000000040000
	CapabilityGetRandomness         uint64 = 0x0000000000080000
	CapabilityPutHmacKey            uint64 = 0x0000000000100000
	CapabilityHmacKeyGenerate       uint64 = 0x0000000000200000
	CapabilityHmacData              uint64 = 0x0000000000400000
	CapabilityHmacVerify            uint64 = 0x0000000000800000
	CapabilityAudit                 uint64 = 0x0000000001000000
	CapabilitySshCertify            uint64 = 0x0000000002000000
	CapabilityGetTemplate           uint64 = 0x0000000004000000
	CapabilityPutTemplate           uint64 = 0x0000000008000000
	CapabilityReset                 uint64 = 0x0000000010000000
	CapabilityOtpDecrypt            uint64 = 0x0000000020000000
	CapabilityOtpAeadCreate         uint64 = 0x0000000040000000
	CapabilityOtpAeadRandom         uint64 = 0x0000000080000000
	CapabilityOtpAeadRewrapFrom     uint64 = 0x0000000100000000
	CapabilityOtpAeadRewrapTo       uint64 = 0x0000000200000000
	CapabilityAttest                uint64 = 0x0000000400000000
	CapabilityPutOtpAeadKey         uint64 = 0x0000000800000000
	CapabilityGenerateOtpAeadKey    uint64 = 0x0000001000000000
	CapabilityWrapData              uint64 = 0x0000002000000000
	CapabilityUnwrapData            uint64 = 0x0000004000000000
	CapabilityDeleteOpaque          uint64 = 0x0000008000000000
	CapabilityDeleteAuthKey         uint64 = 0x0000010000000000
	CapabilityDeleteAsymmetric      uint64 = 0x0000020000000000
	CapabilityDeleteWrapKey         uint64 = 0x0000040000000000
	CapabilityDeleteHmacKey         uint64 = 0x0000080000000000
	CapabilityDeleteTemplate        uint64 = 0x0000100000000000
	CapabilityDeleteOtpAeadKey      uint64 = 0x0000200000000000

	// Domains
	Domain1  uint16 = 0x0001
	Domain2  uint16 = 0x0002
	Domain3  uint16 = 0x0004
	Domain4  uint16 = 0x0008
	Domain5  uint16 = 0x0010
	Domain6  uint16 = 0x0020
	Domain7  uint16 = 0x0040
	Domain8  uint16 = 0x0080
	Domain9  uint16 = 0x0100
	Domain10 uint16 = 0x0200
	Domain11 uint16 = 0x0400
	Domain12 uint16 = 0x0800
	Domain13 uint16 = 0x1000
	Domain14 uint16 = 0x2000
	Domain15 uint16 = 0x4000
	Domain16 uint16 = 0x8000

	// object types
	ObjectTypeOpaque            uint8 = 0x01
	ObjectTypeAuthenticationKey uint8 = 0x02
	ObjectTypeAsymmetricKey     uint8 = 0x03
	ObjectTypeWrapKey           uint8 = 0x04
	ObjectTypeHmacKey           uint8 = 0x05
	ObjectTypeTemplate          uint8 = 0x06
	ObjectTypeOtpAeadKey        uint8 = 0x07

	// list objects params
	ListObjectParamID   uint8 = 0x01
	ListObjectParamType uint8 = 0x02
)
