# yubihsm-go
Yubihsm-go is a minimal implementation of the securechannel and connector protocol of the YubiHSM2.

It also implements a simple SessionManager which keeps connections alive and swaps them if the maximum number of
messages is depleted.

Currently the following commands are implemented:

 * Reset
 * GenerateAsymmetricKey
 * SignDataEddsa
 * SignDataPkcs1
 * PutAsymmetricKey
 * GetPubKey
 * DeriveEcdh
 * Echo
 * ChangeAuthenticationKey
 * PutAuthenticationKey
 * GetOpaque
 * PutOpaque
 * SignAttestationCertificate
 * Authentication & Session related commands
 * GetPseudoRandom

Implementing new commands is really easy. Please consult `commands/constructors.go` and `commands/response.go` for reference.

Please submit a PR if you have implemented new commands or extended existing constructors.

## Example of usage

```go
c := connector.NewHTTPConnector("localhost:1234")
sm, err := yubihsm.NewSessionManager(c, 1, "password", 2)
if err != nil {
	panic(err)
}

echoMessage := []byte("test")

command, err := commands.CreateEchoCommand(echoMessage)
if err != nil {
	panic(err)
}

resp, err := sm.SendEncryptedCommand(command)
if err != nil {
	panic(err)
}

parsedResp, matched := resp.(*commands.EchoResponse)
if !matched {
	panic("invalid response type")
}

if bytes.Equal(parsedResp.Data, echoMessage) {
	println("successfully echoed data")
} else {
	panic(errors.New("echoed message did not equal requested message"))
}

```
