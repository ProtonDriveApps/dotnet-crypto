package main

/*
#include "srp.h"
*/
import "C"
import (
	"bytes"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"runtime/cgo"
	"unsafe"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/clearsign"
	srp "github.com/ProtonMail/go-srp"
	"github.com/ProtonMail/gopenpgp/v3/crypto"
)

type ClientHandshake struct {
	auth                srp.Auth
	expectedServerProof []byte
}

//export srp_get_modulus_verification_key
func srp_get_modulus_verification_key(
	out_key *C.uintptr_t,
) (cErr C.PGP_Error) {
	key, err := crypto.NewKeyFromReaderExplicit(bytes.NewReader([]byte(srp.GetModulusKey())), int8(crypto.Armor))
	if err != nil {
		return errorToPGPError(err)
	}

	*out_key = (C.uintptr_t)(cgo.NewHandle(key))
	return errorToPGPError(nil)
}

//export srp_auth_create
func srp_auth_create(
	handle *C.SRP_CClientCreationHandle,
	verification_key_handle C.uintptr_t,
	out_auth *C.uintptr_t,
) (cErr C.PGP_Error) {
	defer func() {
		if err := recover(); err != nil {
			cErr = errorToPGPError(fmt.Errorf("go panic: %v", err))
		}
	}()

	username := C.GoStringN(handle.username, (C.int)(handle.username_len))
	passwordBytes := unsafe.Slice((*byte)(handle.password), handle.password_len)
	saltBytes := unsafe.Slice((*byte)(handle.salt), handle.salt_len)
	signedModulus := C.GoStringN(handle.signed_modulus, (C.int)(handle.signed_modulus_len))

	key := handleToKey(verification_key_handle)

	auth, err := newAuth(username, passwordBytes, saltBytes, signedModulus, key)
	if err != nil {
		return errorToPGPError(err)
	}

	*out_auth = (C.uintptr_t)(cgo.NewHandle(auth))

	return errorToPGPError(nil)
}

//export srp_auth_derive_verifier
func srp_auth_derive_verifier(
	handle C.uintptr_t,
	verifier_buffer *C.uchar_t,
	verifier_buffer_len C.size_t,
	bit_length C.int,
) (cErr C.PGP_Error) {
	auth := handleToAuth(handle)

	verifierBytes, err := auth.GenerateVerifier(int(bit_length))
	if err != nil {
		return errorToPGPError(err)
	}

	verifierBuffer := unsafe.Slice((*byte)(verifier_buffer), verifier_buffer_len)
	copy(verifierBuffer, verifierBytes)

	return errorToPGPError(nil)
}

//export srp_client_handshake_compute
func srp_client_handshake_compute(
	handle C.uintptr_t,
	server_ephemeral *C.cuchar_t,
	server_ephemeral_len C.size_t,
	client_handshake_buffers *C.SRP_ClientHandshakeBuffers,
	bit_length C.int,
	out_client_exchange *C.uintptr_t,
) (cErr C.PGP_Error) {
	defer func() {
		if err := recover(); err != nil {
			cErr = errorToPGPError(fmt.Errorf("go panic: %v", err))
		}
	}()

	auth := handleToAuth(handle)

	client := &ClientHandshake{auth: *auth}

	auth.ServerEphemeral = unsafe.Slice((*byte)(server_ephemeral), server_ephemeral_len)

	proofs, err := auth.GenerateProofs(int(bit_length))
	if err != nil {
		return errorToPGPError(err)
	}

	proofBuffer := unsafe.Slice((*byte)(client_handshake_buffers.proof_buffer), client_handshake_buffers.proof_buffer_len)
	copy(proofBuffer, proofs.ClientProof)

	ephemeralBuffer := unsafe.Slice((*byte)(client_handshake_buffers.ephemeral_buffer), client_handshake_buffers.ephemeral_buffer_len)
	copy(ephemeralBuffer, proofs.ClientEphemeral)

	client.expectedServerProof = proofs.ExpectedServerProof

	*out_client_exchange = (C.uintptr_t)(cgo.NewHandle(client))

	return errorToPGPError(nil)
}

//export srp_client_handshake_verify_proof
func srp_client_handshake_verify_proof(
	handle C.uintptr_t,
	server_proof *C.cuchar_t,
	server_proof_len C.size_t,
	out_is_valid *C.bool_t,
) (cErr C.PGP_Error) {
	defer func() {
		if err := recover(); err != nil {
			cErr = errorToPGPError(fmt.Errorf("go panic: %v", err))
		}
	}()

	client := handleToClientHandshake(handle)

	serverProof := unsafe.Slice((*byte)(server_proof), server_proof_len)

	*out_is_valid = C.bool_t(client.VerifyProof(serverProof))

	return errorToPGPError(nil)
}

//export srp_auth_destroy
func srp_auth_destroy(handle C.uintptr_t) {
	cgo.Handle(handle).Delete()
}

//export srp_client_handshake_destroy
func srp_client_handshake_destroy(handle C.uintptr_t) {
	cgo.Handle(handle).Delete()
}

//export hash_password
func hash_password(
	password *C.cuchar_t,
	password_len C.size_t,
	salt *C.cuchar_t,
	salt_len C.size_t,
	digest_buffer *C.uchar_t,
	digest_buffer_len C.size_t,
) (cErr C.PGP_Error) {
	defer func() {
		if err := recover(); err != nil {
			cErr = errorToPGPError(fmt.Errorf("go panic: %v", err))
		}
	}()

	passwordBytes := unsafe.Slice((*byte)(password), password_len)
	saltBytes := unsafe.Slice((*byte)(salt), salt_len)

	digest, err := srp.MailboxPassword(passwordBytes, saltBytes)
	if err != nil {
		return errorToPGPError(err)
	}

	digestBuffer := unsafe.Slice((*byte)(digest_buffer), digest_buffer_len)
	copy(digestBuffer, digest)

	return errorToPGPError(nil)
}

func newAuth(
	username string,
	password []byte,
	salt []byte,
	signedModulus string,
	verificationKey *crypto.Key,
) (auth *srp.Auth, err error) {
	base64Modulus, err := readClearSignedMessage(signedModulus, verificationKey)
	if err != nil {
		return
	}

	modulus, err := base64.StdEncoding.DecodeString(base64Modulus)
	if err != nil {
		return
	}

	hashedPassword, err := srp.HashPassword(4, password, username, salt, modulus)
	if err != nil {
		return
	}

	auth = &srp.Auth{Modulus: modulus, HashedPassword: hashedPassword, Version: 4}
	return
}

func readClearSignedMessage(signedMessage string, verificationKey *crypto.Key) (string, error) {
	modulusBlock, rest := clearsign.Decode([]byte(signedMessage))
	if len(rest) != 0 {
		return "", srp.ErrDataAfterModulus
	}

	// TODO: skip armor
	modulusPubkey, err := verificationKey.Armor()
	if err != nil {
		return "", errors.New("pm-srp(cgo): cannot armor modulus pubkey")
	}

	modulusKeyring, err := openpgp.ReadArmoredKeyRing(bytes.NewReader([]byte(modulusPubkey)))
	if err != nil {
		return "", errors.New("pm-srp(cgo): cannot read modulus pubkey")
	}

	_, err = openpgp.CheckDetachedSignature(modulusKeyring, bytes.NewReader(modulusBlock.Bytes), modulusBlock.ArmoredSignature.Body, nil)
	if err != nil {
		return "", srp.ErrInvalidSignature
	}

	return string(modulusBlock.Bytes), nil
}

func (c *ClientHandshake) VerifyProof(serverProof []byte) bool {
	return subtle.ConstantTimeCompare(c.expectedServerProof, serverProof) == 1
}

func handleToAuth(handle C.uintptr_t) *srp.Auth {
	v := cgo.Handle(handle).Value()
	if v == nil {
		panic("could not resolve SRP Auth handle")
	}

	auth, ok := v.(*srp.Auth)
	if !ok {
		panic("handle does not contain an SRP Auth")
	}

	return auth
}

func handleToClientHandshake(handle C.uintptr_t) *ClientHandshake {
	v := cgo.Handle(handle).Value()
	if v == nil {
		panic("could not resolve SRP Client Handshake handle")
	}

	clientHandshake, ok := v.(*ClientHandshake)
	if !ok {
		panic("handle does not contain an SRP Client Handshake")
	}

	return clientHandshake
}
