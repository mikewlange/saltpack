// Copyright 2018 Keybase, Inc. All rights reserved. Use of
// this source code is governed by the included BSD license.

package saltpack

import (
	"testing"

	"github.com/keybase/go-codec/codec"
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

	h := codecHandle()

	var blockV2Bytes1 []byte
	encoder := codec.NewEncoderBytes(&blockV2Bytes1, h)
	blockV2.CodecEncodeSelf(encoder)

	blockV2Bytes2, err := encodeToBytes(blockV2)
	require.NoError(t, err)

	require.Equal(t, blockV2Bytes1, blockV2Bytes2)

	var blockV2Decoded1 encryptionBlockV2
	decoder := codec.NewDecoderBytes(blockV2Bytes1, h)
	blockV2Decoded1.CodecDecodeSelf(decoder)
	require.Equal(t, blockV2, blockV2Decoded1)

	var blockV2Decoded2 encryptionBlockV2
	err = decodeFromBytes(&blockV2Decoded2, blockV2Bytes1)
	require.NoError(t, err)

	require.Equal(t, blockV2, blockV2Decoded2)
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

	var blockV2Decoded encryptionBlockV2
	err = decodeFromBytes([]interface{}{
		&blockV2Decoded.IsFinal,
		&blockV2Decoded.HashAuthenticators,
		&blockV2Decoded.PayloadCiphertext,
	}, blockV2Bytes)
	require.NoError(t, err)

	require.Equal(t, blockV2, blockV2Decoded)
}
