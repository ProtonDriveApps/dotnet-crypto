#ifndef SRP_H
#define SRP_H

#include "common.h"

typedef const struct {
  size_t username_len;
  size_t password_len;
  size_t salt_len;
  size_t signed_modulus_len;
  cchar_t* username;
  cuchar_t* password;
  cuchar_t* salt;
  cchar_t* signed_modulus;
} SRP_CClientCreationHandle;

typedef const struct {
  size_t modulus_len;
  size_t verifier_len;
  cuchar_t* modulus;
  cuchar_t* verifier;
  int bit_length;
} SRP_CServerCreationHandle;

typedef struct {
  size_t proof_buffer_len;
  size_t ephemeral_buffer_len;
  uchar_t* proof_buffer;
  uchar_t* ephemeral_buffer;
} SRP_ClientHandshakeBuffers;

#endif /* SRP_H */