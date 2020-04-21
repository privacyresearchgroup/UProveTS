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

import {
    Zq,
    Attribute,
    SerializedFirstMessage,
    SerializedUProveToken,
    SerializedBaseKeyAndToken,
    DLGroup,
    MultiplicativeGroup,
    ZqField,
    FirstMessage,
    ZqElement,
} from '../datatypes'
import {
    readHexString,
    readFileDataInDictionary,
    performanceTimer,
    readNumberList,
    readVectorElement,
} from '../testutilities/utilities'
import cryptoMath from '../msrcrypto/cryptoMath'
import ECP256 from '../EcP256'
import L2048N256 from '../SubgroupL2048N256'
import { IssuerParams } from '../issuerparams'
import { Prover } from '../prover'
import { computeXArray, computeXt, base64ToUint8Array, uint8ArrayToBase64 } from '../utilities'
import { TestVectorRNG } from '../testutilities/TestVectorRNG'

// tslint:disable: no-string-literal

let totalTime = 0

const testLiteMode = true // lite;
const testECC = true //  ecc;
const testVectorFile = 'testvectors_' + (testECC ? 'EC' : 'SG') + '_D2' + (testLiteMode ? '_lite' : '') + '_doc.txt'
const recommendedParamsFile = 'UProveRecommendedParams' + (testECC ? 'P256' : 'L2048N256') + '.txt'
const params = readFileDataInDictionary(recommendedParamsFile)
const vectors = readFileDataInDictionary(testVectorFile)

class ProverUnitTest {
    numAttribs: number
    t: number
    params: any[]
    vectors: { [k: string]: any }
    useECC: boolean
    Group: DLGroup
    Gq: MultiplicativeGroup
    Zq: ZqField
    ip: IssuerParams
    prover: Prover

    attributes: Attribute[]
    ti: Uint8Array
    pi: Uint8Array

    keyAndToken?: SerializedBaseKeyAndToken[]

    constructor(numAttribs, params, vectors) {
        this.numAttribs = numAttribs
        this.t = numAttribs + 1
        this.params = params
        this.vectors = vectors
        this.useECC = params.OID === '1.3.6.1.4.1.311.75.1.2.1'
        this.Group = this.useECC ? ECP256 : L2048N256
        this.Gq = this.Group.getGq()
        this.Zq = this.Group.getZq()
        this.ip = this.initializeIssuerParameters()
        this.prover = this.initializeProver()
        this.attributes = this.initializeAttributes()

        this.ti = readHexString(vectors['TI'])
        this.pi = readHexString(vectors['PI'])
    }

    initializeIssuerParameters(): IssuerParams {
        const uidp = readHexString(this.vectors['UIDp'])
        const g = this.Group.getPreGenGenerators(this.numAttribs)
        g[0] = readVectorElement(this.Gq, this.vectors, 'g0', this.useECC)
        const e = new Array(this.numAttribs)
        for (let i = 1; i <= this.numAttribs; i++) {
            if (!g[i].equals(readVectorElement(this.Gq, this.params, 'g' + i, this.useECC))) {
                throw new Error(`invalid g${i}`)
            }
            e[i - 1] = readHexString(this.vectors['e' + i])[0] // we only keep the first byte of the returned byte array
        }
        const s = readHexString(this.vectors['S'])
        return new IssuerParams(uidp, this.Group, g, e, s)
    }

    initializeProver(): Prover {
        const testVectorsRNG = TestVectorRNG.create(testLiteMode, this.Zq, this.vectors)
        return new Prover(testVectorsRNG, this.ip)
    }

    initializeAttributes(): Attribute[] {
        const attributes = new Array(this.numAttribs)
        for (let i = 1; i <= this.numAttribs; i++) {
            attributes[i - 1] = readHexString(this.vectors['A' + i])
        }
        return attributes
    }

    loadFirstMessage(): FirstMessage {
        return {
            sz: readVectorElement(this.Gq, this.vectors, 'sigmaZ', this.useECC),
            sa: [readVectorElement(this.Gq, this.vectors, 'sigmaA', this.useECC)],
            sb: [readVectorElement(this.Gq, this.vectors, 'sigmaB', this.useECC)],
        }
    }

    verifyComputation(group, v, vName, isEcGq): boolean {
        return v.equals(readVectorElement(group, this.vectors, vName, isEcGq))
    }
    verifyArrayComputation(v, vName): boolean {
        return cryptoMath.sequenceEqual(v, readHexString(this.vectors[vName]))
    }
}

const proverTest = new ProverUnitTest(5, params, vectors)

test('IssuerParams digest', () => {
    expect(proverTest.verifyArrayComputation(proverTest.ip.computeDigest(), 'P')).toBeTruthy()
})

test('test xi, xt computation', () => {
    const { Zq, attributes, ip, ti } = proverTest
    const x = computeXArray(Zq, attributes, ip.e)
    for (let i = 1; i <= proverTest.numAttribs; i++) {
        expect(proverTest.verifyComputation(Zq, x[i - 1], `x${i}`, false)).toBeTruthy()
    }
    expect(proverTest.verifyComputation(Zq, computeXt(Zq, ip, ti), 'xt', false)).toBeTruthy()
})

test('test second message', () => {
    const { Zq, attributes, ti, pi } = proverTest
    const firstMsg = proverTest.loadFirstMessage()
    const gamma = readVectorElement(proverTest.Gq, proverTest.vectors, 'gamma', proverTest.useECC).toByteArrayUnsigned()
    const t1 = performanceTimer.now()
    const secondMsg = proverTest.prover.generateSecondMessage(1, attributes, ti, pi, Array.from(gamma), firstMsg, false)
    const time = performanceTimer.now() - t1
    totalTime += time

    console.log(`Generate second message time: ${time}`)
    expect(
        proverTest.verifyComputation(
            Zq,
            Zq.createModElementFromBytes(base64ToUint8Array(secondMsg.sc[0])),
            'sigmaC',
            false
        )
    ).toBeTruthy()
})

test('generate token', () => {
    const { prover, Gq, Zq, useECC } = proverTest
    const thirdMsg = {
        sr: [(readVectorElement(Zq, vectors, 'sigmaR', false) as unknown) as ZqElement],
    }
    const t1 = performanceTimer.now()
    proverTest.keyAndToken = prover.generateTokens(thirdMsg)
    const time = performanceTimer.now() - t1
    console.log(`generate token time: ${time}`)
    totalTime += time
    const token = proverTest.keyAndToken[0].token
    expect(
        proverTest.verifyComputation(Gq, Gq.createElementFromBytes(base64ToUint8Array(token.h)), 'h', useECC)
    ).toBeTruthy()
    expect(
        proverTest.verifyComputation(
            Gq,
            Gq.createElementFromBytes(base64ToUint8Array(token.szp)),
            'sigmaZPrime',
            useECC
        )
    ).toBeTruthy()
    expect(
        proverTest.verifyComputation(
            Zq,
            Zq.createModElementFromBytes(base64ToUint8Array(token.scp)),
            'sigmaCPrime',
            false
        )
    ).toBeTruthy()
    expect(
        proverTest.verifyComputation(
            Zq,
            Zq.createModElementFromBytes(base64ToUint8Array(token.srp)),
            'sigmaRPrime',
            false
        )
    ).toBeTruthy()
})

test('generate proof', () => {
    const { prover, Gq, Zq, useECC, ip, ti, pi, attributes } = proverTest

    const keyAndBaseToken = proverTest.keyAndToken!
    const token: SerializedUProveToken = {
        ...keyAndBaseToken[0].token,
        uidp: uint8ArrayToBase64(ip.uidp),
        ti: uint8ArrayToBase64(ti),
        pi: uint8ArrayToBase64(pi),
    }
    const { key } = keyAndBaseToken[0]

    const disclosed = readNumberList(vectors['D'])
    const committed = null
    const undisclosed = readNumberList(vectors['U'])
    const message = readHexString(vectors['m'])
    const messageD = readHexString(vectors['md'])
    const scopeData = null
    const commitmentPrivateValues = {}
    const t1 = performanceTimer.now()
    const ukat = ip.ParseKeyAndToken({ key, token })

    const proof = prover.generateProof(
        ukat,
        disclosed,
        committed || [],
        message,
        messageD,
        attributes,
        scopeData,
        commitmentPrivateValues
    )
    const time = performanceTimer.now() - t1
    const dSize = disclosed.length

    console.log(`generateProof time: ${time}`)
    expect(proverTest.verifyArrayComputation(base64ToUint8Array(proof!.a), 'a')).toBeTruthy()
    if (!testLiteMode) {
        expect(proverTest.verifyArrayComputation(base64ToUint8Array(proof!.ap), 'ap')).toBeTruthy()
    }
    if (!testLiteMode) {
        expect(
            proverTest.verifyComputation(Gq, Gq.createElementFromBytes(base64ToUint8Array(proof!.Ps)), 'Ps', useECC)
        ).toBeTruthy()
    }
    expect(
        proverTest.verifyComputation(Zq, Zq.createModElementFromBytes(base64ToUint8Array(proof!.r[0])), 'r0', false)
    ).toBeTruthy()
    for (let i = 1; i <= undisclosed.length; i++) {
        expect(
            proverTest.verifyComputation(
                Zq,
                Zq.createModElementFromBytes(base64ToUint8Array(proof!.r[i])),
                'r' + undisclosed[i - 1],
                false
            )
        ).toBeTruthy()
    }
})
