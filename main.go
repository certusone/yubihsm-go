package main

import (
	"aiakos/commands"
	"aiakos/connector"
	"aiakos/securechannel"
	"fmt"
)

func main() {

	channel, err := securechannel.NewSecureChannel(connector.NewHTTPConnector("127.0.0.1:12345"), 1, "password")
	if err != nil {
		panic(err)
	}

	err = channel.Authenticate()
	if err != nil {
		panic(err)
	}

	cmd, _ := commands.CreateGenerateAsymmetricKeyCommand(2, []byte("myKey"), commands.Domain1, commands.CapabilityAsymmetricSignEddsa, commands.AlgorighmED25519)
	res, err := channel.SendEncryptedCommand(cmd)
	if err != nil {
		fmt.Printf("%v\n", err)
	}

	fmt.Printf("%v\n", res)

	cmd, _ = commands.CreateSignDataEddsaCommand(2, []byte("my test message"))
	res, err = channel.SendEncryptedCommand(cmd)
	if err != nil {
		fmt.Printf("%v\n", err)
	}

	fmt.Printf("signature: %v\n", res)

	cmd, _ = commands.CreateResetCommand()
	_, err = channel.SendEncryptedCommand(cmd)
	if err != nil {
		panic(err)
	}
}
