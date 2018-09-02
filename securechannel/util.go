package securechannel

import (
	"bytes"
	"crypto/aes"
)

// pad adds a padding to src until using the mechanism specified in SCP03 until it has a len that is a multiple of
// aes.BlockSize and returns the result
func pad(src []byte) []byte {
	if aes.BlockSize-len(src)%aes.BlockSize == 0 {
		return src
	}

	padding := aes.BlockSize - len(src)%aes.BlockSize - 1
	padtext := bytes.Repeat([]byte{0}, padding)
	padtext = append([]byte{0x80}, padtext...)
	return append(src, padtext...)
}

// unpad removes the padding from src using the mechanism specified in SCP03 and returns the result
func unpad(src []byte) []byte {
	if src[len(src)-1] != 0x00 && src[len(src)-1] != 0x80 {
		return src
	}

	padLen := 0
	for i := len(src) - 1; i >= 0; i-- {
		if src[i] == 0x00 {
			padLen++
			continue
		}
		if src[i] == 0x80 {
			padLen++
			break
		}
	}

	return src[:len(src)-padLen]
}
