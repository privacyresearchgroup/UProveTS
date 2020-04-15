/*
 * Created April 2020
 *
 * Copyright (c) 2020 Privacy Research, LLC
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

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
    SerializedIssuerParams,
    base64string,
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
import { ZqRNG } from './testutilities/ZqRNG'

interface PartialFirstMessage {
    sa: GroupElement
    sb: GroupElement
}

export interface SerializedIssuerSession {
    ip: SerializedIssuerParams
    ti: base64string
    attributes: Attribute[]
    numTokens: number
    firstMessage?: SerializedFirstMessage
    secondMessage?: SerializedSecondMessage
    thirdMessage?: SerializedThirdMessage
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
        ti: Uint8Array,
        firstMessage?: FirstMessage,
        secondMessage?: SecondMessage,
        thirdMessage?: ThirdMessage
    ) {
        this.ip = ip
        this._w = Array(this._numTokens)
        for (let i = 0; i < this._numTokens; ++i) {
            this._w[i] = rng.getRandomZqElement()
        }
        this.Gq = ip.descGq.getGq()
        this.Zq = ip.descGq.getZq()
        this.attributes = attributes
        this.ti = ti

        this._gamma = this._computeGamma()

        this.firstMessage = firstMessage
        this.secondMessage = secondMessage
        this.thirdMessage = thirdMessage
    }

    setW(w: ZqElement[]): void {
        this._w = w
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
        const g = this.ip.descGq.getGenerator()
        const sigmaA = this._modExp(g, w)
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

    _serializeFirstMessage(): SerializedFirstMessage {
        return {
            sz: uint8ArrayToBase64(this.firstMessage!.sz.toByteArrayUnsigned()),
            sa: this.firstMessage!.sa.map((sa: GroupElement) => uint8ArrayToBase64(sa.toByteArrayUnsigned())),
            sb: this.firstMessage!.sb.map((sb: GroupElement) => uint8ArrayToBase64(sb.toByteArrayUnsigned())),
        }
    }

    getFirstMessage(): SerializedFirstMessage {
        if (!this.firstMessage) {
            this._prepareFirstMessages()
        }
        return this._serializeFirstMessage()
    }

    receiveSecondMessage(secondMsg: SerializedSecondMessage): void {
        const sc = secondMsg.sc.map((b64: string) => this.Zq.createElementFromBytes(base64ToUint8Array(b64)))
        this.secondMessage = { sc }
    }

    _serializeSecondMessage(): SerializedSecondMessage {
        const sc = this.secondMessage!.sc.map((n: ZqElement) => uint8ArrayToBase64(n.toByteArrayUnsigned()))
        return sc && { sc }
    }

    getThirdMessage(): SerializedThirdMessage {
        if (!this.thirdMessage) {
            this._prepareThirdMessage()
        }
        return this._serializeThirdMessage()
    }

    _serializeThirdMessage(): SerializedThirdMessage {
        return {
            sr: this.thirdMessage!.sr.map((sr: ZqElement) => uint8ArrayToBase64(sr.toByteArrayUnsigned())),
        }
    }

    serialize(): SerializedIssuerSession {
        const ip = this.ip.serialize()
        const ti = uint8ArrayToBase64(this.ti)
        const { attributes } = this
        const numTokens = this._numTokens
        const firstMessage = this.firstMessage && this._serializeFirstMessage()
        const secondMessage = this.secondMessage && this._serializeSecondMessage()
        const thirdMessage = this.thirdMessage && this._serializeThirdMessage()

        return {
            ip,
            ti,
            attributes,
            numTokens,
            firstMessage,
            secondMessage,
            thirdMessage,
        }
    }

    serializeW(): base64string[] {
        return this._w.map((w: ZqElement) => uint8ArrayToBase64(w.toByteArrayUnsigned()))
    }

    static loadIssuerSession(
        ser: SerializedIssuerSession,
        pkc: PrivateKeyContainer,
        w: base64string[],
        rng?: RandomNumberGenerator
    ): IssuerSession {
        const ip = IssuerParams.ParseIssuerParams(ser.ip)
        const Zq = ip.descGq.getZq()
        const ws = w.map((b64: string) => Zq.createElementFromBytes(base64ToUint8Array(b64)))
        rng = rng || new ZqRNG(Zq)
        const ti = base64ToUint8Array(ser.ti)
        const fm = ser.firstMessage && ip.ParseFirstMessage(ser.firstMessage)
        const sm = ser.secondMessage && {
            sc: ser.secondMessage.sc.map((b64: string) => Zq.createElementFromBytes(base64ToUint8Array(b64))),
        }
        const tm = ser.thirdMessage && ip.ParseThirdMessage(ser.thirdMessage)
        const is = new IssuerSession(pkc, ser.numTokens, rng, ip, ser.attributes, ti, fm, sm, tm)
        is.setW(ws)
        return is
    }
}
