/*
 * Created April 2020
 *
 * Copyright (c) 2020 Privacy Research, LLC
 *
 *  Licensed under GPL v3 (https://www.gnu.org/licenses/gpl-3.0.en.html)
 *
 *  This code is a modification of Microsoft Research's U-Prove
 *  Javascript SDK (https://www.microsoft.com/en-us/download/details.aspx?id=52491). These
 *  portions are Copyright (c) Microsoft.  Changes to these portions include reorganization
 *  and addition of type information.
 */

import { Hash } from '../hash'
import { readFileDataInDictionary, readHexString } from '../testutilities/utilities'

import cryptoMath from '../msrcrypto/cryptoMath'
import L2048N256 from '../SubgroupL2048N256'
import ECP256 from '../EcP256'
import cryptoECC from '../msrcrypto/cryptoECC'

const vectors = readFileDataInDictionary('testvectors_hashing.txt')

const bytesx0102030405 = readHexString('0102030405')

test('hash_byte (0x01)', () => {
    const testCase = 'hash_byte (0x01)'
    const H = new Hash()
    H.updateByte(0x01)
    const expectedValue = '4bf5122f344554c53bde2ebb8cd2b7e3d1600ad631c385a5d7cce23c7785459a'
    const digest = H.digest()
    const hexDigest = Buffer.from(digest).toString('hex')
    expect(hexDigest).toBe(expectedValue)
    expect(cryptoMath.sequenceEqual(digest, readHexString(vectors[testCase]))).toBeTruthy()
})

test('hash_octetstring (0x0102030405', () => {
    const testCase = 'hash_octectstring (0x0102030405)'
    const H = new Hash()
    H.updateBytes(bytesx0102030405)
    expect(cryptoMath.sequenceEqual(H.digest(), readHexString(vectors[testCase]))).toBeTruthy()
})

test('hash_null (null)', () => {
    const testCase = 'hash_null (null)'
    const H = new Hash()
    H.updateNull()
    expect(cryptoMath.sequenceEqual(H.digest(), readHexString(vectors[testCase]))).toBeTruthy()
})

test('"hash_list [0x01, 0x0102030405, null]', () => {
    const testCase = 'hash_list [0x01, 0x0102030405, null]'
    const H = new Hash()
    H.updateUint32(3)
    H.updateByte(0x01)
    H.updateBytes(bytesx0102030405)
    H.updateNull()
    expect(cryptoMath.sequenceEqual(H.digest(), readHexString(vectors[testCase]))).toBeTruthy()
})

// TODO: get curve definitions

test('hash_group (1.3.6.1.4.1.311.75.1.1.1)', () => {
    const testCase = 'hash_group (1.3.6.1.4.1.311.75.1.1.1)'
    const H = new Hash()
    const Gq = L2048N256
    Gq.updateHash(H)
    expect(cryptoMath.sequenceEqual(H.digest(), readHexString(vectors[testCase]))).toBeTruthy()
})

test('hash_group (1.3.6.1.4.1.311.75.1.2.1)', () => {
    const testCase = 'hash_group (1.3.6.1.4.1.311.75.1.2.1)'
    const H = new Hash()
    const Gq = ECP256
    Gq.updateHash(H)

    expect(cryptoMath.sequenceEqual(H.digest(), readHexString(vectors[testCase]))).toBeTruthy()
})

test('hash_group wrong_group (1.3.6.1.4.1.311.75.1.2.1)', () => {
    const testCase = 'hash_group (1.3.6.1.4.1.311.75.1.2.1)'
    const H = new Hash()
    const Gq = ECP256
    Gq.p256 = cryptoECC.createP384()
    Gq.updateHash(H)

    expect(cryptoMath.sequenceEqual(H.digest(), readHexString(vectors[testCase]))).toBeFalsy()
})
