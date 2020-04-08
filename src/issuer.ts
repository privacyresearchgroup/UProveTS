import { IssuerParams } from './issuerparams'
import {
    ZqElement,
    RandomNumberGenerator,
    IssuerParamsData,
    IssuerParamsFunctions,
    GroupElement,
    MultiplicativeGroup,
    ZqField,
    Attribute,
    FirstMessage,
    SerializedFirstMessage,
    SecondMessage,
    ThirdMessage,
    SerializedSecondMessage,
    SerializedThirdMessage,
} from './datatypes'
import {
    computeXArray,
    computeXt,
    multiModExp,
    uint8ArrayToBase64,
    base64ToUint8Array,
    ATimesBPlusCModQ,
} from './utilities'
import { PrivateKeyContainer } from './PrivateKeyContainer'

interface PartialFirstMessage {
    sa: GroupElement
    sb: GroupElement
}
export class IssuerSession {
    ip: IssuerParams
    private _w: ZqElement[]
    private _gamma: GroupElement

    Gq: MultiplicativeGroup
    Zq: ZqField

    attributes: Attribute[]
    ti: Uint8Array

    firstMessage?: FirstMessage
    secondMessage?: SecondMessage
    thirdMessage?: ThirdMessage

    constructor(
        private _pkc: PrivateKeyContainer,
        private _numTokens: number,
        rng: RandomNumberGenerator,
        ip: IssuerParamsData & IssuerParamsFunctions,
        attributes: Attribute[],
        ti: Uint8Array
    ) {
        this.ip = ip
        this._w = Array(_numTokens)
        for (let i = 0; i < _numTokens; ++i) {
            this._w[i] = rng.getRandomZqElement()
        }
        this.Gq = ip.descGq.getGq()
        this.Zq = ip.descGq.getZq()
        this.attributes = attributes
        this.ti = ti

        console.log(`this._w`, this._w)
        this._gamma = this._computeGamma()
    }

    private _prepareFirstMessages(): void {
        const y0: ZqElement = this.Zq.createElementFromBytes(this._pkc.getPrivateKeyBytes())
        const sigmaZ = this._modExp(this._gamma, y0)

        const sasb = this._w.map((w: ZqElement) => this._computeFirstMessage(w))
        this.firstMessage = {
            sz: sigmaZ,
            sa: sasb.map((entry: PartialFirstMessage) => entry.sa),
            sb: sasb.map((entry: PartialFirstMessage) => entry.sb),
        }
    }

    private _prepareThirdMessage(): void {
        if (!this.firstMessage && this.secondMessage) {
            throw new Error(`attempting to generate third message out of sequence`)
        }
        const y0: ZqElement = this.Zq.createElementFromBytes(this._pkc.getPrivateKeyBytes())
        const sigmaRs = this.secondMessage!.sc.map((sc: ZqElement, idx: number) => this._sigmaR(sc, y0, this._w[idx]))
        this.thirdMessage = {
            sr: sigmaRs,
        }
    }

    private _computeFirstMessage(w: ZqElement): PartialFirstMessage {
        const sigmaA = this._modExp(this.ip.g[0], w)
        const sigmaB = this._modExp(this._gamma, w)
        return { sa: sigmaA, sb: sigmaB }
    }
    private _computeGamma(): GroupElement {
        const x = computeXArray(this.Zq, this.attributes, this.ip.e)
        x.unshift(this.Zq.createElementFromInteger(1)) // exponent 1 for g0
        x.push(computeXt(this.Zq, this.ip, this.ti))
        // compute gamma = g0 * g1^x1 * ... * gn^xn * gt^xt
        const gamma = multiModExp(this.Gq, this.ip.g, x)
        return gamma
    }

    private _modExp(g: GroupElement, a: ZqElement): GroupElement {
        const temp = this.Gq.getIdentityElement()
        this.Gq.modexp(g, a, temp)
        return temp
    }
    private _sigmaR(sigmaC: ZqElement, y0: ZqElement, w: ZqElement): ZqElement {
        return ATimesBPlusCModQ(this.Zq, sigmaC, y0, w)
    }

    getFirstMessage(): SerializedFirstMessage {
        if (!this.firstMessage) {
            this._prepareFirstMessages()
        }
        return {
            sz: uint8ArrayToBase64(this.firstMessage!.sz.toByteArrayUnsigned()),
            sa: this.firstMessage!.sa.map((sa: GroupElement) => uint8ArrayToBase64(sa.toByteArrayUnsigned())),
            sb: this.firstMessage!.sb.map((sb: GroupElement) => uint8ArrayToBase64(sb.toByteArrayUnsigned())),
        }
    }

    receiveSecondMessage(secondMsg: SerializedSecondMessage): void {
        const sc = secondMsg.sc.map((b64: string) => this.Zq.createElementFromBytes(base64ToUint8Array(b64)))
        this.secondMessage = { sc }
    }

    getThirdMessage(): SerializedThirdMessage {
        if (!this.thirdMessage) {
            this._prepareThirdMessage()
        }
        return {
            sr: this.thirdMessage!.sr.map((sr: ZqElement) => uint8ArrayToBase64(sr.toByteArrayUnsigned())),
        }
    }
}
