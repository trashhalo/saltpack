package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"syscall/js"

	"github.com/keybase/saltpack"
	"github.com/keybase/saltpack/basic"
)

func JsResult(res js.Value, err js.Value) js.Value {
	return js.ValueOf([]interface{}{res, err})
}

func JsError(err error) js.Value {
	errCon := js.Global().Get("Error")
	return JsResult(js.Null(), errCon.New(err.Error()))
}

func JsOk(val interface{}) js.Value {
	return JsResult(js.ValueOf(val), js.Null())
}

func KeyGen(this js.Value, args []js.Value) interface{} {
	keyring := basic.NewKeyring()

	signer, err := keyring.GenerateSigningKey()
	if err != nil {
		return JsError(err)
	}

	signingVal := wrapSigningKey(signer)

	return JsOk(map[string]interface{}{
		"signing": signingVal,
	})
}

func wrapSigningKey(key *basic.SigningSecretKey) js.Value {
	enc := base64.StdEncoding

	signingSecretKey := *key.GetRawSecretKey()
	signingPublicKey := *key.GetRawPublicKey()
	return js.ValueOf(map[string]interface{}{
		"type":    js.ValueOf("signing"),
		"public":  enc.EncodeToString(signingPublicKey[:]),
		"private": enc.EncodeToString(signingSecretKey[:]),
	})
}

func unwrapSigningPubKey(val js.Value) (*basic.SigningPublicKey, error) {
	enc := base64.StdEncoding

	pubB, err := enc.DecodeString(val.String())
	if err != nil {
		return nil, err
	}

	var pub [ed25519.PublicKeySize]byte
	for i, v := range pubB {
		pub[i] = v
	}

	key := basic.NewSigningPublicKey(&pub)
	return &key, nil
}

func unwrapSigningKey(val js.Value) (*basic.SigningSecretKey, error) {
	enc := base64.StdEncoding

	priStr := val.Get("private").String()
	priB, err := enc.DecodeString(priStr)
	if err != nil {
		return nil, err
	}

	var pri [ed25519.PrivateKeySize]byte
	for i, v := range priB {
		pri[i] = v
	}

	pubStr := val.Get("public").String()
	pubB, err := enc.DecodeString(pubStr)
	if err != nil {
		return nil, err
	}

	var pub [ed25519.PublicKeySize]byte
	for i, v := range pubB {
		pub[i] = v
	}

	key := basic.NewSigningSecretKey(&pub, &pri)
	return &key, nil
}

func SignValue(this js.Value, args []js.Value) interface{} {
	signer, err := unwrapSigningKey(args[0])
	if err != nil {
		return JsError(err)
	}

	msg := []byte(args[1].String())

	signed, err := saltpack.SignArmor62(saltpack.CurrentVersion(), msg, *signer, "")
	if err != nil {
		return JsError(err)
	}

	return JsOk(signed)
}

func VerifyValue(this js.Value, args []js.Value) interface{} {
	keyring := basic.NewKeyring()

	key, err := unwrapSigningPubKey(args[0])
	if err != nil {
		return JsError(err)
	}

	signed := args[1].String()

	foundKey, verifiedMsg, _, err := saltpack.Dearmor62Verify(saltpack.CheckKnownMajorVersion, signed, keyring)
	if err != nil {
		return JsError(err)
	}

	if !saltpack.PublicKeyEqual(key, foundKey) {
		return JsError(fmt.Errorf("keys do not match"))
	}

	return JsOk(string(verifiedMsg))
}

func main() {
	js.Global().Set("keyGen", js.FuncOf(KeyGen))
	js.Global().Set("signValue", js.FuncOf(SignValue))
	js.Global().Set("verifyValue", js.FuncOf(VerifyValue))
	select {}
}
