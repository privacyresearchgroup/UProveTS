import { Attribute, DLGroup, MultiplicativeGroup, ZqField, ZqElement } from '../datatypes'
import { IssuerParams } from '../issuerparams'
import { Prover } from '../prover'
import ECP256 from '../EcP256'
import L2048N256 from '../SubgroupL2048N256'
import { readHexString, readVectorElement, readFileDataInDictionary } from '../testutilities/utilities'
import { IssuerSession } from '../issuer'
import { ZqRNG } from '../testutilities/ZqRNG'
import { InMemoryPrivateKeyContainer } from '../PrivateKeyContainer'

let totalTime: number
totalTime = 0

const testLiteMode = true // lite;
const testECC = true //  ecc;
const testVectorFile = 'testvectors_' + (testECC ? 'EC' : 'SG') + '_D2' + (testLiteMode ? '_lite' : '') + '_doc.txt'
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
    }

    initializeIssuerParameters(): IssuerParams {
        const uidp = readHexString(this._vectors.UIDp)
        const g = this.Group.getPreGenGenerators(this._numAttributes)

        // TODO: use y0!
        g[0] = readVectorElement(this.Gq, this._vectors, 'g0', this.useECC)
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

    initializeAttributes(): Attribute[] {
        const attributes = new Array(this._numAttributes)
        for (let i = 1; i <= this._numAttributes; i++) {
            attributes[i - 1] = readHexString(this._vectors['A' + i])
        }
        return attributes
    }
}

const protocolTest = new FullProtocolUnitTest(5, params, vectors)

test('run protocol', () => {
    const firstMsg = protocolTest.issuerSession.getFirstMessage()
    console.log({ firstMsg })
    expect(firstMsg).toBeDefined()
    expect(firstMsg.sa.length).toEqual(1)
    expect(firstMsg.sb.length).toEqual(1)

    expect(firstMsg.sa[0]).toBeDefined()
    expect(firstMsg.sb[0]).toBeDefined()
})
