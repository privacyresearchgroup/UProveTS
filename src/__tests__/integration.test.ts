/*
 * Created April 2020
 *
 * Copyright (c) 2020 Privacy Research, LLC
 *
 *  Licensed under GPL v3 (https://www.gnu.org/licenses/gpl-3.0.en.html)
 *
 */

import fetch from 'node-fetch'
import { IssuerParams } from '../issuerparams'
import {
    SerializedFirstMessage,
    SerializedThirdMessage,
    SerializedSecondMessage,
    SerializedUProveToken,
} from '../datatypes'
import { Prover } from '../prover'
import { ZqRNG } from '../testutilities/ZqRNG'
import { base64ToUint8Array, uint8ArrayToBase64 } from '../utilities'
import { readFileDataInDictionary } from '../testutilities/utilities'
import { Verifier } from '../verifier'
import { AttributeSet } from '../AttributeSet'

const apidata = readFileDataInDictionary('apidata.txt')
const apikey = apidata.uproveissuer
const testURL = apidata.url
const attributes = AttributeSet.fromJSON({
    sub: '406baf85-24af-44bd-ba23-1e38a955796d',
    username: 'Surullinen Weil',
    email: 'sw@example.com',
    avatar: 'https://news.artnet.com/app/news-upload/2017/08/NO45-1024x1024.jpg',
    phoneNumber: '800-867-5309',
})

const initialData = {
    ti: 'VG9rZW4gaW5mb3JtYXRpb24gZmllbGQgdmFsdWU=',
    // attributes: [[73, 150, 2, 210], [65, 108, 105, 99, 101, 32, 83, 109, 105, 116, 104], [85, 83, 65], [2], [25]],
    attributes: attributes.encode(),
}

interface StartSessionResponse {
    id: string
    firstMessage: SerializedFirstMessage
}

async function getParamsFromAPI(): Promise<IssuerParams> {
    const result = await fetch(`${testURL}/ip`, {
        method: 'get',
        headers: { 'x-api-key': apikey },
    })
    const sip = await result.json()
    console.log(sip)
    return IssuerParams.ParseIssuerParams(sip)
}

async function startSession(): Promise<StartSessionResponse> {
    const result = await fetch(`${testURL}/session`, {
        method: 'post',
        headers: { 'x-api-key': apikey },
        body: JSON.stringify(initialData),
    })
    const rsp = await result.json()
    console.log(rsp)
    return rsp
}

async function completeSession(id: string, secondMessage: SerializedSecondMessage): Promise<SerializedThirdMessage> {
    const result = await fetch(`${testURL}/session/${id}`, {
        method: 'post',
        headers: { 'x-api-key': apikey },
        body: JSON.stringify({ secondMessage }),
    })
    const rsp = await result.json()
    console.log(rsp)
    return rsp.thirdMessage
}

test('test get issuer params', async () => {
    jest.setTimeout(20000)
    const ip = await getParamsFromAPI()
    expect(ip).toBeDefined()
})

test('test full proof', async () => {
    jest.setTimeout(20000)
    const ip = await getParamsFromAPI()
    expect(ip).toBeDefined()

    const pi = Uint8Array.from([1])

    const prover = new Prover(new ZqRNG(ip.descGq.getZq()), ip)

    const { id, firstMessage } = await startSession()
    const secondMessage = prover.generateSecondMessage(
        1,
        initialData.attributes,
        base64ToUint8Array(initialData.ti),
        pi,
        null,
        ip.ParseFirstMessage(firstMessage),
        true
    )
    const serializedThirdMessage = await completeSession(id, secondMessage)
    const thirdMessage = ip.ParseThirdMessage(serializedThirdMessage)
    console.log(serializedThirdMessage)
    expect(thirdMessage).toBeDefined()

    // Prover generates tokens
    const keyAndBaseToken = prover.generateTokens(thirdMessage)
    // console.log({ keyAndToken: keyAndBaseToken })
    expect(keyAndBaseToken).toBeDefined()
    expect(keyAndBaseToken[0]).toBeDefined()
    expect(keyAndBaseToken[0].key).toBeDefined()
    expect(keyAndBaseToken[0].token).toBeDefined()

    // Prover generates proof

    const token: SerializedUProveToken = {
        ...keyAndBaseToken[0].token,
        uidp: uint8ArrayToBase64(ip.uidp),
        ti: initialData.ti,
        pi: uint8ArrayToBase64(pi),
    }
    const { key } = keyAndBaseToken[0]

    const disclosed = [2, 3, 5]
    const committed = null
    const message = Uint8Array.from([72, 101, 108, 108, 111, 32, 119, 111, 114, 108, 100])
    const messageD = Uint8Array.from([66, 121, 101])
    const scopeData = {
        p: 1,
        s: Uint8Array.from([
            48,
            50,
            57,
            55,
            57,
            97,
            53,
            97,
            45,
            52,
            99,
            101,
            48,
            45,
            52,
            48,
            56,
            48,
            45,
            98,
            98,
            49,
            48,
            45,
            99,
            99,
            51,
            101,
            101,
            57,
            57,
            100,
            102,
            50,
            97,
            101,
        ]),
    }
    const commitmentPrivateValues = {}
    const ukat = ip.ParseKeyAndToken({ key, token })

    const proof = prover.generateProof(
        ukat,
        disclosed,
        committed || [],
        message,
        messageD,
        initialData.attributes,
        scopeData,
        commitmentPrivateValues
    )

    expect(proof).toBeDefined()

    const verifier = new Verifier(ip)
    expect(verifier.verifyTokenSignature(ukat.token)).toBe(true)

    const parsedProof = verifier.parseProof(proof)

    const isValid = verifier.verify(parsedProof, ukat.token, disclosed, [], message, scopeData, messageD)
    // console.log(isValid)
    // console.log(protocolTest.ip.serialize())
    // console.log(uint8ArrayToBase64(protocolTest.y0.toByteArrayUnsigned()))
    // console.log(protocolTest.issuerSession.serialize())
    expect(isValid).toBe(true)
})

test('cannot disclose pseudonym attribute', async () => {
    jest.setTimeout(20000)
    const ip = await getParamsFromAPI()
    expect(ip).toBeDefined()

    const pi = Uint8Array.from([1])

    const prover = new Prover(new ZqRNG(ip.descGq.getZq()), ip)

    const { id, firstMessage } = await startSession()
    const secondMessage = prover.generateSecondMessage(
        1,
        initialData.attributes,
        base64ToUint8Array(initialData.ti),
        pi,
        null,
        ip.ParseFirstMessage(firstMessage),
        true
    )
    const serializedThirdMessage = await completeSession(id, secondMessage)
    const thirdMessage = ip.ParseThirdMessage(serializedThirdMessage)
    console.log(serializedThirdMessage)
    expect(thirdMessage).toBeDefined()

    // Prover generates tokens
    const keyAndBaseToken = prover.generateTokens(thirdMessage)
    // console.log({ keyAndToken: keyAndBaseToken })
    expect(keyAndBaseToken).toBeDefined()
    expect(keyAndBaseToken[0]).toBeDefined()
    expect(keyAndBaseToken[0].key).toBeDefined()
    expect(keyAndBaseToken[0].token).toBeDefined()

    // Prover generates proof

    const token: SerializedUProveToken = {
        ...keyAndBaseToken[0].token,
        uidp: uint8ArrayToBase64(ip.uidp),
        ti: initialData.ti,
        pi: uint8ArrayToBase64(pi),
    }
    const { key } = keyAndBaseToken[0]

    const disclosed = [1, 2, 3, 5]
    const committed = null
    const message = Uint8Array.from([72, 101, 108, 108, 111, 32, 119, 111, 114, 108, 100])
    const messageD = Uint8Array.from([66, 121, 101])
    const scopeData = {
        p: 1,
        s: Uint8Array.from([
            48,
            50,
            57,
            55,
            57,
            97,
            53,
            97,
            45,
            52,
            99,
            101,
            48,
            45,
            52,
            48,
            56,
            48,
            45,
            98,
            98,
            49,
            48,
            45,
            99,
            99,
            51,
            101,
            101,
            57,
            57,
            100,
            102,
            50,
            97,
            101,
        ]),
    }
    const commitmentPrivateValues = {}
    const ukat = ip.ParseKeyAndToken({ key, token })

    expect(() =>
        prover.generateProof(
            ukat,
            disclosed,
            committed || [],
            message,
            messageD,
            initialData.attributes,
            scopeData,
            commitmentPrivateValues
        )
    ).toThrow()
})

test('test full proof with commitments', async () => {
    jest.setTimeout(20000)
    const ip = await getParamsFromAPI()
    expect(ip).toBeDefined()

    const pi = Uint8Array.from([1])

    const prover = new Prover(new ZqRNG(ip.descGq.getZq()), ip)

    const { id, firstMessage } = await startSession()
    const secondMessage = prover.generateSecondMessage(
        1,
        initialData.attributes,
        base64ToUint8Array(initialData.ti),
        pi,
        null,
        ip.ParseFirstMessage(firstMessage),
        true
    )
    const serializedThirdMessage = await completeSession(id, secondMessage)
    const thirdMessage = ip.ParseThirdMessage(serializedThirdMessage)
    console.log(serializedThirdMessage)
    expect(thirdMessage).toBeDefined()

    // Prover generates tokens
    const keyAndBaseToken = prover.generateTokens(thirdMessage)
    // console.log({ keyAndToken: keyAndBaseToken })
    expect(keyAndBaseToken).toBeDefined()
    expect(keyAndBaseToken[0]).toBeDefined()
    expect(keyAndBaseToken[0].key).toBeDefined()
    expect(keyAndBaseToken[0].token).toBeDefined()

    // Prover generates proof

    const token: SerializedUProveToken = {
        ...keyAndBaseToken[0].token,
        uidp: uint8ArrayToBase64(ip.uidp),
        ti: initialData.ti,
        pi: uint8ArrayToBase64(pi),
    }
    const { key } = keyAndBaseToken[0]

    const disclosed = [2, 3, 5]
    const committed = [4]
    const message = Uint8Array.from([72, 101, 108, 108, 111, 32, 119, 111, 114, 108, 100])
    const messageD = Uint8Array.from([66, 121, 101])
    const scopeData = {
        p: 1,
        s: Uint8Array.from([
            48,
            50,
            57,
            55,
            57,
            97,
            53,
            97,
            45,
            52,
            99,
            101,
            48,
            45,
            52,
            48,
            56,
            48,
            45,
            98,
            98,
            49,
            48,
            45,
            99,
            99,
            51,
            101,
            101,
            57,
            57,
            100,
            102,
            50,
            97,
            101,
        ]),
    }
    const commitmentPrivateValues = {}
    const ukat = ip.ParseKeyAndToken({ key, token })

    const proof = prover.generateProof(
        ukat,
        disclosed,
        committed || [],
        message,
        messageD,
        initialData.attributes,
        scopeData,
        commitmentPrivateValues
    )

    // should not generate proof with commitment for disclosed attribute
    expect(() => {
        prover.generateProof(
            ukat,
            disclosed,
            [2],
            message,
            messageD,
            initialData.attributes,
            scopeData,
            commitmentPrivateValues
        )
    }).toThrow()
    console.log({ commitmentPrivateValues })
    expect(Object.keys(commitmentPrivateValues).length).toBe(1)

    expect(proof).toBeDefined()

    const verifier = new Verifier(ip)
    expect(verifier.verifyTokenSignature(ukat.token)).toBe(true)

    const parsedProof = verifier.parseProof(proof)

    const isValid = verifier.verify(parsedProof, ukat.token, disclosed, committed || [], message, scopeData, messageD)
    // console.log(isValid)
    // console.log(protocolTest.ip.serialize())
    // console.log(uint8ArrayToBase64(protocolTest.y0.toByteArrayUnsigned()))
    // console.log(protocolTest.issuerSession.serialize())
    expect(isValid).toBe(true)
})
