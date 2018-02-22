// Copyright 2018 Keybase, Inc. All rights reserved. Use of
// this source code is governed by the included BSD license.

package saltpack

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// Test that the encoded field order for encryptionBlockV2 puts
// IsFinal first.
func TestEncryptedBlockV2Serialization(t *testing.T) {
	isFinal := true
	hashAuthenticators := []payloadAuthenticator{{0x1}, {0x2}}
	payloadCiphertext := []byte("some ciphertext")

	blockV2 := encryptionBlockV2{
		encryptionBlockV1: encryptionBlockV1{
			HashAuthenticators: hashAuthenticators,
			PayloadCiphertext:  payloadCiphertext,
		},
		IsFinal: isFinal,
	}

	blockV2Bytes, err := encodeToBytes(blockV2)
	require.NoError(t, err)

	blockV2Fields := []interface{}{isFinal, hashAuthenticators, payloadCiphertext}
	expectedBytes, err := encodeToBytes(blockV2Fields)
	require.NoError(t, err)

	require.Equal(t, expectedBytes, blockV2Bytes)
}
