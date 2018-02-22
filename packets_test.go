// Copyright 2018 Keybase, Inc. All rights reserved. Use of
// this source code is governed by the included BSD license.

package saltpack

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// Test that encryptedBlockV2 encodes and decodes properly.
func TestEncryptedBlockV2RoundTrip(t *testing.T) {
	isFinal := false
	hashAuthenticators := []payloadAuthenticator{{0x1}, {0x2}}
	payloadCiphertext := []byte("TestEncryptedBlockV2RoundTrip")

	blockV2 := encryptionBlockV2{
		encryptionBlockV1: encryptionBlockV1{
			HashAuthenticators: hashAuthenticators,
			PayloadCiphertext:  payloadCiphertext,
		},
		IsFinal: isFinal,
	}

	blockV2Bytes1, err := blockV2.MarshalBinary()
	require.NoError(t, err)

	blockV2Bytes2, err := encodeToBytes(blockV2)
	require.NoError(t, err)

	require.Equal(t, blockV2Bytes1, blockV2Bytes2)

	var blockV2Unmarshalled encryptionBlockV2
	err = blockV2Unmarshalled.UnmarshalBinary(blockV2Bytes1)
	require.NoError(t, err)
	require.Equal(t, blockV2, blockV2Unmarshalled)

	var blockV2Decoded encryptionBlockV2
	decodeFromBytes(&blockV2Decoded, blockV2Bytes1)
	require.Equal(t, blockV2, blockV2Decoded)
}

// Test that the encoded field order for encryptionBlockV2 puts
// IsFinal first.
func TestEncryptedBlockV2FieldOrder(t *testing.T) {
	isFinal := true
	hashAuthenticators := []payloadAuthenticator{{0x3}, {0x4}}
	payloadCiphertext := []byte("TestEncryptedBlockV2FieldOrder")

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
