/** @file
  AES Wrapper Implementation over OpenSSL EVP (Envelope) interface.

Copyright (c) 2010 - 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "InternalCryptLib.h"
#include <openssl/evp.h>

typedef struct {
  CONST UINT8       *Key;
  CONST EVP_CIPHER  *EvpCipher;
} AES_CONTEXT;

/**
  Retrieves the size, in bytes, of the context buffer required for AES operations.

  @return  The size, in bytes, of the context buffer required for AES operations.

**/
UINTN
EFIAPI
AesGetContextSize (
  VOID
  )
{
  //
  // Store Key locally to provide it to the worker functions
  //
  return (UINTN) sizeof (AES_CONTEXT);
}

/**
  Initializes user-supplied memory as AES context for subsequent use.

  This function initializes user-supplied memory pointed by AesContext as AES context.
  In addition, it sets up all AES key materials for subsequent encryption and decryption
  operations.
  There are 3 options for key length, 128 bits, 192 bits, and 256 bits.

  If AesContext is NULL, then return FALSE.
  If Key is NULL, then return FALSE.
  If KeyLength is not valid, then return FALSE.

  @param[out]  AesContext  Pointer to AES context being initialized.
  @param[in]   Key         Pointer to the user-supplied AES key.
  @param[in]   KeyLength   Length of AES key in bits.

  @retval TRUE   AES context initialization succeeded.
  @retval FALSE  AES context initialization failed.

**/
BOOLEAN
EFIAPI
AesInit (
  OUT  VOID         *AesContext,
  IN   CONST UINT8  *Key,
  IN   UINTN        KeyLength
  )
{
  AES_CONTEXT *Context = AesContext;

  //
  // Check input parameters.
  //
  if ((AesContext == NULL) || (Key == NULL) || ((KeyLength != 128) && (KeyLength != 192) && (KeyLength != 256))) {
    return FALSE;
  }

  //
  // Store AES Key and EVP Cipher inside the user-provided Context
  //
  Context->Key = Key;

  switch (KeyLength) {
    case 128:
      Context->EvpCipher = EVP_aes_128_cbc();
      break;
    case 192:
      Context->EvpCipher = EVP_aes_192_cbc();
      break;
    case 256:
      Context->EvpCipher = EVP_aes_256_cbc();
      break;
    default:
      return FALSE;
  }

  return TRUE;
}

/**
  Performs AES encryption on a data buffer of the specified size in CBC mode.

  This function performs AES encryption on data buffer pointed by Input, of specified
  size of InputSize, in CBC mode.
  InputSize must be multiple of block size (16 bytes). This function does not perform
  padding. Caller must perform padding, if necessary, to ensure valid input data size.
  Initialization vector should be one block size (16 bytes).
  AesContext should be already correctly initialized by AesInit(). Behavior with
  invalid AES context is undefined.

  If AesContext is NULL, then return FALSE.
  If Input is NULL, then return FALSE.
  If InputSize is not multiple of block size (16 bytes), then return FALSE.
  If Ivec is NULL, then return FALSE.
  If Output is NULL, then return FALSE.

  @param[in]   AesContext  Pointer to the AES context.
  @param[in]   Input       Pointer to the buffer containing the data to be encrypted.
  @param[in]   InputSize   Size of the Input buffer in bytes.
  @param[in]   Ivec        Pointer to initialization vector.
  @param[out]  Output      Pointer to a buffer that receives the AES encryption output.

  @retval TRUE   AES encryption succeeded.
  @retval FALSE  AES encryption failed.

**/
BOOLEAN
EFIAPI
AesCbcEncrypt (
  IN   VOID         *AesContext,
  IN   CONST UINT8  *Input,
  IN   UINTN        InputSize,
  IN   CONST UINT8  *Ivec,
  OUT  UINT8        *Output
  )
{
  AES_CONTEXT     *Context = AesContext;
  EVP_CIPHER_CTX  *EvpContext;
  INT32           OutputSize;
  INT32           TempSize;

  //
  // Check input parameters.
  //
  if ((AesContext == NULL) || (Input == NULL) || ((InputSize % AES_BLOCK_SIZE) != 0)) {
    return FALSE;
  }

  if ((Ivec == NULL) || (Output == NULL) || (InputSize > INT_MAX)) {
    return FALSE;
  }

  EvpContext = EVP_CIPHER_CTX_new();
  if (EvpContext == NULL) {
    return FALSE;
  }

  //
  // Perform AES data encryption with CBC mode
  //
  if (EVP_EncryptInit_ex(EvpContext, Context->EvpCipher, NULL, Context->Key, Ivec) != 1) {
    EVP_CIPHER_CTX_free(EvpContext);
    return FALSE;
  }

  //
  // Disable padding to match the software-based implementation
  //
  EVP_CIPHER_CTX_set_padding (EvpContext, 0);

  if (EVP_EncryptUpdate(EvpContext, Output, &OutputSize, Input, (INT32) InputSize) != 1) {
    EVP_CIPHER_CTX_free(EvpContext);
    return FALSE;
  }

  if (EVP_EncryptFinal_ex(EvpContext, Output + OutputSize, &TempSize) != 1) {
    EVP_CIPHER_CTX_free(EvpContext);
    return FALSE;
  }

  EVP_CIPHER_CTX_free(EvpContext);
  return TRUE;
}

/**
  Performs AES decryption on a data buffer of the specified size in CBC mode.

  This function performs AES decryption on data buffer pointed by Input, of specified
  size of InputSize, in CBC mode.
  InputSize must be multiple of block size (16 bytes). This function does not perform
  padding. Caller must perform padding, if necessary, to ensure valid input data size.
  Initialization vector should be one block size (16 bytes).
  AesContext should be already correctly initialized by AesInit(). Behavior with
  invalid AES context is undefined.

  If AesContext is NULL, then return FALSE.
  If Input is NULL, then return FALSE.
  If InputSize is not multiple of block size (16 bytes), then return FALSE.
  If Ivec is NULL, then return FALSE.
  If Output is NULL, then return FALSE.

  @param[in]   AesContext  Pointer to the AES context.
  @param[in]   Input       Pointer to the buffer containing the data to be encrypted.
  @param[in]   InputSize   Size of the Input buffer in bytes.
  @param[in]   Ivec        Pointer to initialization vector.
  @param[out]  Output      Pointer to a buffer that receives the AES encryption output.

  @retval TRUE   AES decryption succeeded.
  @retval FALSE  AES decryption failed.

**/
BOOLEAN
EFIAPI
AesCbcDecrypt (
  IN   VOID         *AesContext,
  IN   CONST UINT8  *Input,
  IN   UINTN        InputSize,
  IN   CONST UINT8  *Ivec,
  OUT  UINT8        *Output
  )
{
  AES_CONTEXT     *Context = AesContext;
  EVP_CIPHER_CTX  *EvpContext;
  INT32           OutputSize;
  INT32           TempSize;

  //
  // Check input parameters.
  //
  if ((AesContext == NULL) || (Input == NULL) || ((InputSize % AES_BLOCK_SIZE) != 0)) {
    return FALSE;
  }

  if ((Ivec == NULL) || (Output == NULL) || (InputSize > INT_MAX)) {
    return FALSE;
  }

  EvpContext = EVP_CIPHER_CTX_new();
  if (EvpContext == NULL) {
    return FALSE;
  }

  //
  // Perform AES data decryption with CBC mode
  //
  if (EVP_DecryptInit_ex(EvpContext, Context->EvpCipher, NULL, Context->Key, Ivec) != 1) {
    EVP_CIPHER_CTX_free(EvpContext);
    return FALSE;
  }

  //
  // Disable padding to match the software-based implementation
  //
  EVP_CIPHER_CTX_set_padding (EvpContext, 0);

  if (EVP_DecryptUpdate(EvpContext, Output, &OutputSize, Input, (INT32) InputSize) != 1) {
    EVP_CIPHER_CTX_free(EvpContext);
    return FALSE;
  }

  if (EVP_DecryptFinal_ex(EvpContext, Output + OutputSize, &TempSize) != 1) {
    EVP_CIPHER_CTX_free(EvpContext);
    return FALSE;
  }

  EVP_CIPHER_CTX_free(EvpContext);
  return TRUE;
}
