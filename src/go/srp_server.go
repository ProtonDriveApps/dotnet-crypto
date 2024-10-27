package main

/*
#include "srp.h"
*/
import "C"
import (
	"fmt"
	"runtime/cgo"
	"unsafe"

	srp "github.com/ProtonMail/go-srp"
)

//export srp_server_generate_handshake
func srp_server_generate_handshake(
	handle *C.SRP_CServerCreationHandle,
	secret *C.cuchar_t,
	secret_len C.size_t,
	ephemeral_buffer *C.uchar_t,
	ephemeral_buffer_len C.size_t,
	out_server_handshake *C.uintptr_t,
) (cErr C.PGP_Error) {
	defer func() {
		if err := recover(); err != nil {
			cErr = errorToPGPError(fmt.Errorf("go panic: %v", err))
		}
	}()

	modulusBytes := unsafe.Slice((*byte)(handle.modulus), (C.int)(handle.modulus_len))
	verifierBytes := unsafe.Slice((*byte)(handle.verifier), (C.int)(handle.verifier_len))

	var err error
	var server *srp.Server

	if secret != nil {
		secretBytes := unsafe.Slice((*byte)(secret), (C.int)(secret_len))
		server, err = srp.NewServerWithSecret(modulusBytes, verifierBytes, secretBytes, int(handle.bit_length))
	} else {
		server, err = srp.NewServer(modulusBytes, verifierBytes, int(handle.bit_length))
	}

	if err != nil {
		return errorToPGPError(err)
	}

	serverEphemeralBytes, err := server.GenerateChallenge()
	if err != nil {
		return errorToPGPError(err)
	}

	ephemeralBuffer := unsafe.Slice((*byte)(ephemeral_buffer), (C.int)(ephemeral_buffer_len))
	copy(ephemeralBuffer, serverEphemeralBytes)

	*out_server_handshake = (C.uintptr_t)(cgo.NewHandle(server))

	return errorToPGPError(nil)
}

//export srp_server_compute_exchange
func srp_server_compute_exchange(
	handle C.uintptr_t,
	client_proof *C.cuchar_t,
	client_proof_len C.size_t,
	client_ephemeral *C.cuchar_t,
	client_ephemeral_len C.size_t,
	server_proof_buffer *C.uchar_t,
	server_proof_buffer_len C.size_t,
) (cErr C.PGP_Error) {
	defer func() {
		if err := recover(); err != nil {
			cErr = errorToPGPError(fmt.Errorf("go panic: %v", err))
		}
	}()

	server := handleToServer(handle)

	clientProofBytes := unsafe.Slice((*byte)(client_proof), (C.int)(client_proof_len))
	clientEphemeralBytes := unsafe.Slice((*byte)(client_ephemeral), (C.int)(client_ephemeral_len))

	serverProofBytes, err := server.VerifyProofs(clientEphemeralBytes, clientProofBytes)
	if err != nil {
		return errorToPGPError(err)
	}

	serverProofBuffer := unsafe.Slice((*byte)(server_proof_buffer), (C.int)(server_proof_buffer_len))
	copy(serverProofBuffer, serverProofBytes)

	return errorToPGPError(nil)
}

//export srp_server_destroy
func srp_server_destroy(handle C.uintptr_t) {
	cgo.Handle(handle).Delete()
}

func handleToServer(handle C.uintptr_t) *srp.Server {
	v := cgo.Handle(handle).Value()
	if v == nil {
		panic("could not resolve SRP Server handle")
	}

	server, ok := v.(*srp.Server)
	if !ok {
		panic("handle does not contain an SRP Server")
	}

	return server
}
