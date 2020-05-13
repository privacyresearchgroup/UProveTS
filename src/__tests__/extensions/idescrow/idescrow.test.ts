/*
 * Created April 2020
 *
 * Copyright (c) 2020 Privacy Research, LLC
 *
 *  Licensed under GPL v3 (https://www.gnu.org/licenses/gpl-3.0.en.html)
 *
 */

import {
    Attribute,
    DLGroup,
    MultiplicativeGroup,
    ZqField,
    ZqElement,
    SerializedUProveToken,
    ScopeData,
} from '../../../datatypes'
import { IssuerParams } from '../../../issuerparams'
import { Prover } from '../../../prover'
import ECP256 from '../../../EcP256'
import L2048N256 from '../../../SubgroupL2048N256'
import {
    readHexString,
    readVectorElement,
    readFileDataInDictionary,
    readNumberList,
    performanceTimer,
} from '../../../testutilities/utilities'
import { IssuerSession } from '../../../issuer'
import { ZqRNG } from '../../../testutilities/ZqRNG'
import { InMemoryPrivateKeyContainer } from '../../../PrivateKeyContainer'
import { uint8ArrayToBase64, computeTokenId, computeX } from '../../../utilities'
import { Verifier } from '../../../verifier'
import { AttributeSet } from '../../..'
import { Auditor } from '../../../extensions/idescrow/Auditor'
import { VerifiableEncrypter } from '../../../extensions/idescrow/VerifiableEncrypter'
import { IDEscrowVerifier } from '../../../extensions/idescrow/IDEscrowVerifier'
import cryptoMath from '../../../msrcrypto/cryptoMath'

let totalTime: number
totalTime = 0

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

const testECC = true //  ecc;
const testVectorFile = 'testvectors_' + (testECC ? 'EC' : 'SG') + '_D2' + '_doc.txt'
const recommendedParamsFile = 'UProveRecommendedParams' + (testECC ? 'P256' : 'L2048N256') + '.txt'
const params = readFileDataInDictionary(recommendedParamsFile)
const vectors = readFileDataInDictionary(testVectorFile)

class FullProtocolUnitTest {
    t: number
    useECC: boolean
    Group: DLGroup
    Gq: MultiplicativeGroup
    Zq: ZqField
    ip: IssuerParams
    prover: Prover
    issuerSession: IssuerSession
    auditor: Auditor

    y0: ZqElement

    attributes: Attribute[]
    ti: Uint8Array
    pi: Uint8Array

    rng: ZqRNG

    constructor(private _numAttributes: number, private _params: any, private _vectors: { [k: string]: any }) {
        this.t = _numAttributes + 1
        this.useECC = _params.OID === '1.3.6.1.4.1.311.75.1.2.1'
        this.Group = this.useECC ? ECP256 : L2048N256
        this.Gq = this.Group.getGq()
        this.Zq = this.Group.getZq()
        this.rng = new ZqRNG(this.Zq)
        this.y0 = this.rng.getRandomZqElement()

        this.ti = readHexString(_vectors.TI)
        this.pi = readHexString(_vectors.PI)

        this.ip = this.initializeIssuerParameters()
        this.prover = this.initializeProver()
        this.attributes = this.initializeAttributes()
        this.issuerSession = this.initializeIssuerSession()
        this.auditor = this.initializeAuditor()
    }

    initializeIssuerParameters(): IssuerParams {
        const uidp = readHexString(this._vectors.UIDp)
        const g = this.Group.getPreGenGenerators(this._numAttributes)

        const g0base = this.Group.getGenerator()
        const g0 = this.Gq.getIdentityElement()
        this.Gq.modexp(g0base, this.y0, g0)
        g[0] = g0
        const e = new Array(this._numAttributes)
        for (let i = 1; i <= this._numAttributes; i++) {
            if (!g[i].equals(readVectorElement(this.Gq, this._params, 'g' + i, this.useECC))) {
                throw new Error(`invalid g${i}`)
            }
            e[i - 1] = readHexString(this._vectors['e' + i])[0] // we only keep the first byte of the returned byte array
        }
        const s = readHexString(this._vectors.S)
        return new IssuerParams(uidp, this.Group, g, e, s)
    }

    initializeProver(): Prover {
        return new Prover(this.rng, this.ip)
    }

    initializeIssuerSession(): IssuerSession {
        const pkc = new InMemoryPrivateKeyContainer(Uint8Array.from(this.y0.toByteArrayUnsigned()))
        return new IssuerSession(pkc, 1, this.rng, this.ip, this.attributes, this.ti)
    }

    initializeAuditor(): Auditor {
        const auditorSecret = this.rng.getRandomZqElement().toByteArrayUnsigned()
        const pkc = new InMemoryPrivateKeyContainer(Uint8Array.from(auditorSecret))
        return new Auditor(pkc, this.ip)
    }
    initializeAttributes(): Attribute[] {
        return initialData.attributes
    }
}

const protocolTest = new FullProtocolUnitTest(5, params, vectors)

test('run protocol with ID escrow', () => {
    // Issuer creates the first message
    const firstMsg = protocolTest.issuerSession.getFirstMessage()
    expect(firstMsg).toBeDefined()
    expect(firstMsg.sa.length).toEqual(1)
    expect(firstMsg.sb.length).toEqual(1)

    expect(firstMsg.sa[0]).toBeDefined()
    expect(firstMsg.sb[0]).toBeDefined()

    // Prover parses it and creates the second message
    console.log({ firstMsg })
    const proverFirstMsg = protocolTest.prover.ip.ParseFirstMessage(firstMsg)
    const secondMsg = protocolTest.prover.generateSecondMessage(
        1,
        protocolTest.attributes,
        protocolTest.ti,
        protocolTest.pi,
        null,
        proverFirstMsg,
        true
    )
    expect(secondMsg).toBeDefined()
    expect(secondMsg.sc.length).toEqual(1)

    // Issuer creates third message
    protocolTest.issuerSession.receiveSecondMessage(secondMsg)
    const thirdMessage = protocolTest.issuerSession.getThirdMessage()

    expect(thirdMessage).toBeDefined()

    // Prover generates tokens
    const proverThirdMessage = protocolTest.prover.ip.ParseThirdMessage(thirdMessage)
    const keyAndBaseToken = protocolTest.prover.generateTokens(proverThirdMessage)
    // console.log({ keyAndToken: keyAndBaseToken })
    expect(keyAndBaseToken).toBeDefined()
    expect(keyAndBaseToken[0]).toBeDefined()
    expect(keyAndBaseToken[0].key).toBeDefined()
    expect(keyAndBaseToken[0].token).toBeDefined()

    // Prover generates proof

    const token: SerializedUProveToken = {
        ...keyAndBaseToken[0].token,
        uidp: uint8ArrayToBase64(protocolTest.ip.uidp),
        ti: uint8ArrayToBase64(protocolTest.ti),
        pi: uint8ArrayToBase64(protocolTest.pi),
    }
    const { key } = keyAndBaseToken[0]

    const commit = 3 // commit the email address
    const disclosed = [2]
    const committed = [commit]
    const message = readHexString(vectors.m)
    const messageD = readHexString(vectors.md)
    const scopeData: ScopeData = { p: 1, s: Uint8Array.from([90, 11, 117, 103, 103, 108, 97]) }
    const commitmentPrivateValues: { tildeO: ZqElement[] } = { tildeO: [] }
    const t1 = performanceTimer.now()
    const ukat = protocolTest.ip.ParseKeyAndToken({ key, token })

    const proof = protocolTest.prover.generateProof(
        ukat,
        disclosed,
        committed,
        message,
        messageD,
        protocolTest.attributes,
        scopeData,
        commitmentPrivateValues
    )
    const time = performanceTimer.now() - t1
    // console.log(`generate proof time: ${time}`)

    expect(proof).toBeDefined()
    expect(proof.tc).toBeDefined()
    expect(proof.tc?.length).toEqual(1)

    console.log({ proof })

    const verifier = new Verifier(protocolTest.ip)
    expect(verifier.verifyTokenSignature(ukat.token)).toBe(true)

    const parsedProof = verifier.parseProof(proof)

    const isValid = verifier.verify(parsedProof, ukat.token, disclosed, committed, message, scopeData, messageD)
    // console.log(isValid)
    // console.log(protocolTest.ip.serialize())
    // console.log(uint8ArrayToBase64(protocolTest.y0.toByteArrayUnsigned()))
    // console.log(protocolTest.issuerSession.serialize())
    expect(isValid).toBe(true)

    // test that prover can compute the pseudonym correctly
    const pseudo = protocolTest.prover.computePseudonym(scopeData, protocolTest.attributes)
    expect(pseudo).toBe(proof.Ps)

    // perform verifiable encryption
    const ve = new VerifiableEncrypter(protocolTest.ip, protocolTest.rng)

    // commitmentBytes is the byte array version go the group element C_i
    const commitmentBytes = parsedProof.tc![0]?.toByteArrayUnsigned()
    const ieProof = ve.verifiableEncrypt(
        protocolTest.auditor,
        ukat.token,
        Uint8Array.from([32, 32, 32, 32]),
        commitmentPrivateValues.tildeO[0],
        commitmentBytes,
        commit,
        protocolTest.attributes[commit - 1]
    )
    console.log({ ieProof })

    // verify it
    const vev = new IDEscrowVerifier(protocolTest.ip, protocolTest.auditor)
    const encryptionValid = vev.verify(ieProof, computeTokenId(ukat.token), parsedProof.tc![0])
    console.log({ encryptionValid })
    expect(encryptionValid).toBeTruthy()

    // decrypt it
    const decrypted = protocolTest.auditor.decrypt(ieProof)
    const xb = computeX(protocolTest.Zq, protocolTest.attributes[commit - 1], protocolTest.ip.e[commit - 1])
    const g = protocolTest.ip.descGq.getGenerator()
    const g2xb = protocolTest.Gq.getIdentityElement()
    protocolTest.Gq.modexp(g, xb, g2xb)
    console.log(`verifiably decrypted`, {
        xb: xb.toByteArrayUnsigned(),
        Pb: decrypted.toByteArrayUnsigned(),
        g2xb: g2xb.toByteArrayUnsigned(),
    })

    expect(cryptoMath.sequenceEqual(decrypted.toByteArrayUnsigned(), g2xb.toByteArrayUnsigned())).toBeTruthy()
})
