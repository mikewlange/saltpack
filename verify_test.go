// Copyright 2015 Keybase, Inc. All rights reserved. Use of
// this source code is governed by the included BSD license.

package saltpack

import (
	"bytes"
	"encoding/hex"
	"errors"
	"io"
	"io/ioutil"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVerifyVersionValidator(t *testing.T) {
	in := []byte{0x01}
	key := newSigPrivKey(t)
	smg, err := Sign(Version1(), in, key)
	require.NoError(t, err)

	_, _, err = Verify(SingleVersionValidator(Version2()), smg, kr)
	require.NotNil(t, err)
}

func testVerify(t *testing.T, version Version) {
	in := randomMsg(t, 128)
	key := newSigPrivKey(t)
	smsg, err := Sign(version, in, key)
	require.NoError(t, err)
	skey, msg, err := Verify(SingleVersionValidator(version), smsg, kr)
	require.NoError(t, err, "input:      %x\nsigned msg: %x", in, smsg)
	assert.True(t, PublicKeyEqual(skey, key.GetPublicKey()),
		"sender key %x, expected %x", skey.ToKID(), key.GetPublicKey().ToKID())
	assert.Equal(t, in, msg)
}

func testVerifyNewMinorVersion(t *testing.T, version Version) {
	in := []byte{0x01}

	newVersion := version
	newVersion.Minor++

	tso := testSignOptions{
		corruptHeader: func(sh *SignatureHeader) {
			sh.Version = newVersion
		},
	}
	key := newSigPrivKey(t)
	smg, err := testTweakSign(version, in, key, tso)
	require.NoError(t, err)

	_, _, err = Verify(SingleVersionValidator(newVersion), smg, kr)
	require.NoError(t, err)
}

func testVerifyConcurrent(t *testing.T, version Version) {
	in := randomMsg(t, 128)
	key := newSigPrivKey(t)
	smsg, err := Sign(version, in, key)
	require.NoError(t, err)

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			skey, msg, err := Verify(SingleVersionValidator(version), smsg, kr)
			if !assert.NoError(t, err, "input:      %x\nsigned msg: %x", in, smsg) {
				// Don't fall through, as the tests below will panic.
				return
			}
			assert.True(t, PublicKeyEqual(skey, key.GetPublicKey()),
				"sender key %x, expected %x", skey.ToKID(), key.GetPublicKey().ToKID())
			assert.Equal(t, in, msg)
		}()
	}
	wg.Wait()
}

type emptySigKeyring struct{}

func (k emptySigKeyring) LookupSigningPublicKey(kid []byte) SigningPublicKey { return nil }

func testVerifyEmptyKeyring(t *testing.T, version Version) {
	in := randomMsg(t, 128)
	key := newSigPrivKey(t)
	smsg, err := Sign(version, in, key)
	require.NoError(t, err)

	_, _, err = Verify(SingleVersionValidator(version), smsg, emptySigKeyring{})
	require.Equal(t, ErrNoSenderKey, err)
}

func testVerifyDetachedEmptyKeyring(t *testing.T, version Version) {
	key := newSigPrivKey(t)
	msg := randomMsg(t, 128)
	sig, err := SignDetached(version, msg, key)
	require.NoError(t, err)

	_, err = VerifyDetached(SingleVersionValidator(version), msg, sig, emptySigKeyring{})
	require.Equal(t, ErrNoSenderKey, err)
}

func testVerifyErrorAtEOF(t *testing.T, version Version) {
	in := randomMsg(t, 128)
	key := newSigPrivKey(t)
	smsg, err := Sign(version, in, key)
	require.NoError(t, err)

	var reader io.Reader = bytes.NewReader(smsg)
	errAtEOF := errors.New("err at EOF")
	reader = errAtEOFReader{reader, errAtEOF}
	_, stream, err := NewVerifyStream(SingleVersionValidator(version), reader, kr)
	require.NoError(t, err)

	msg, err := ioutil.ReadAll(stream)
	requireErrSuffix(t, err, errAtEOF.Error())

	// Since the bytes are still verified, the verified message
	// should still compare equal to the original input.
	assert.Equal(t, in, msg)
}

func TestVerify(t *testing.T) {
	tests := []func(*testing.T, Version){
		testVerify,
		testVerifyNewMinorVersion,
		testVerifyConcurrent,
		testVerifyEmptyKeyring,
		testVerifyDetachedEmptyKeyring,
		testVerifyErrorAtEOF,
	}
	runTestsOverVersions(t, "test", tests)
}

type pubkeyOnlySigKeyring struct{}

func (p pubkeyOnlySigKeyring) LookupSigningPublicKey(kid []byte) SigningPublicKey {
	return newSigPubKey(kid)
}

const hardcodedV1SignedMessage = `
BEGIN KEYBASE SALTPACK SIGNED MESSAGE. kXR7VktZdyH7rvq v5wcIkHbsMGwMrf
bu4PmUTnBUI2QWi Nu9smFqPCiRfB9h PAUmWFHLkTKGMdN tdrKMtkDu0UhJEj 7gM6Tt8OeykFHq9
R4FnzgakB19YwYa CGVfWxxXpK9OaMI S00BurzWOWBXIxe EoTHvgyx1oHUVdX HRNjJCXTvsSJVa8
Qyg3bN37HAfS8ek gZG6JflV06S2Olp gLdhxNZKIo2zF9P sD5pDFXvoVVzeNC D4vZtMiNQrniEYo
qY903nTYqyGQ4yl UULZ6yP14CcSPfg 8r8CXVi5Z2. END KEYBASE SALTPACK SIGNED
MESSAGE.
`

const hardcodedVerifyKey = "f596585d050597c03a87d653c4be89f7327dbd86b921dd05acfc9df33eb7a962"

func TestHardcodedSignedMessageV1(t *testing.T) {
	decodedKey, err := hex.DecodeString(hardcodedVerifyKey)
	require.NoError(t, err)
	keyring := pubkeyOnlySigKeyring{}
	signer, plaintext, _, err := Dearmor62Verify(SingleVersionValidator(Version1()), hardcodedV1SignedMessage, keyring)
	require.NoError(t, err)
	require.Equal(t, "test message!", string(plaintext))
	require.Equal(t, decodedKey, signer.ToKID())
}

const hardcodedV1DetachedSignature = `
BEGIN KEYBASE SALTPACK DETACHED SIGNATURE. kXR7VktZdyH7rvq v5wcIkPOwOUCix9
HfoZZdGgIjzeYWi Nu9smFqPCiRfB9h PAUmWFHLkUaLXQd DTZrK37uaKi9dgf 60zJCgqbheQLTVP
Vr2Dw2x1MLOenwI dt3P0dRsyh2WvQW OeqH28kbuzPiA0f OPQ0Y26dpV8A8uE DUDdJed0edSYEbx
v. END KEYBASE SALTPACK DETACHED SIGNATURE.
`

func TestHardcodedDetachedSignatureV1(t *testing.T) {
	decodedKey, err := hex.DecodeString(hardcodedVerifyKey)
	require.NoError(t, err)
	keyring := pubkeyOnlySigKeyring{}
	signer, _, err := Dearmor62VerifyDetached(SingleVersionValidator(Version1()), []byte("test message!"), hardcodedV1DetachedSignature, keyring)
	require.NoError(t, err)
	require.Equal(t, decodedKey, signer.ToKID())
}
