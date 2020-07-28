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
    IssuerParamsData,
    IssuerParamsFunctions,
    DLGroup,
    GroupElement,
    FirstMessage,
    SerializedFirstMessage,
    ThirdMessage,
    SerializedThirdMessage,
    KeyAndToken,
    SerializedKeyAndToken,
    SerializedIssuerParams,
} from './datatypes'
import { Hash } from './hash'
import { base64ToUint8Array, base64ToArray, uint8ArrayToBase64 } from './utilities'
import L2048N256 from './SubgroupL2048N256'
import ECP256 from './EcP256'
import Curve25519 from './Curve25519'

export class IssuerParams implements IssuerParamsData, IssuerParamsFunctions {
    uidp: Uint8Array
    descGq: DLGroup
    e: number[]
    g: GroupElement[]
    s: Uint8Array
    P?: Uint8Array

    constructor(uidp: Uint8Array, descGq: DLGroup, g: GroupElement[], e: number[], s: Uint8Array) {
        this.uidp = uidp
        this.descGq = descGq
        this.g = g
        this.e = e
        this.s = s
    }

    isValid(): boolean {
        return true
    }

    get t(): number {
        return this.e.length + 1
    }

    computeDigest(): Uint8Array {
        if (this.P === undefined) {
            const H = new Hash()
            H.updateBytes(this.uidp)
            this.descGq.updateHash(H)
            H.updateListOfIntegers(this.g)
            H.updateListOfBytes(this.e)
            H.updateBytes(this.s)
            this.P = H.digest()
        }
        return this.P
    }

    ParseFirstMessage(fmObj: SerializedFirstMessage): FirstMessage {
        try {
            if (!fmObj.sz || !fmObj.sa || !fmObj.sb || fmObj.sa.length !== fmObj.sb.length) {
                throw new Error('invalid serialization')
            }

            const Gq = this.descGq.getGq()

            const sz = Gq.createElementFromBytes(base64ToUint8Array(fmObj.sz))
            const numberOfTokens = fmObj.sa.length
            const sa = new Array(numberOfTokens)
            const sb = new Array(numberOfTokens)
            for (let i = 0; i < numberOfTokens; i++) {
                sa[i] = Gq.createElementFromBytes(base64ToUint8Array(fmObj.sa[i]))
                sb[i] = Gq.createElementFromBytes(base64ToUint8Array(fmObj.sb[i]))
            }
            return { sz, sa, sb }
        } catch (e) {
            throw new Error(`can't parse first message: ${e}`)
        }
    }

    ParseThirdMessage(tmObj: SerializedThirdMessage): ThirdMessage {
        try {
            if (!tmObj.sr) {
                throw new Error('invalid serialization')
            }

            const Zq = this.descGq.getZq()

            const numberOfTokens = tmObj.sr.length
            const sr = new Array(numberOfTokens)
            for (let i = 0; i < numberOfTokens; i++) {
                sr[i] = Zq.createElementFromBytes(base64ToUint8Array(tmObj.sr[i]))
            }
            return { sr }
        } catch (e) {
            throw new Error(`can't parse third message: ${e}`)
        }
    }

    ParseKeyAndToken(ukatObj: SerializedKeyAndToken): KeyAndToken {
        const Gq = this.descGq.getGq()
        const Zq = this.descGq.getZq()
        try {
            if (
                !ukatObj.token ||
                !ukatObj.key ||
                !ukatObj.token.uidp ||
                !ukatObj.token.h ||
                !ukatObj.token.szp ||
                !ukatObj.token.scp ||
                !ukatObj.token.srp
            ) {
                throw new Error('invalid serialization')
            }

            const token = {
                uidp: base64ToUint8Array(ukatObj.token.uidp),
                h: Gq.createElementFromBytes(base64ToUint8Array(ukatObj.token.h)),
                ti: ukatObj.token.ti ? base64ToUint8Array(ukatObj.token.ti) : null, // TODO: can we make these undefined?
                pi: ukatObj.token.pi ? base64ToUint8Array(ukatObj.token.pi) : null,
                szp: Gq.createElementFromBytes(base64ToUint8Array(ukatObj.token.szp)),
                scp: Zq.createElementFromBytes(base64ToUint8Array(ukatObj.token.scp)),
                srp: Zq.createElementFromBytes(base64ToUint8Array(ukatObj.token.srp)),
                d: false,
            }
            const key = Zq.createElementFromBytes(base64ToUint8Array(ukatObj.key))

            return { token, key }
        } catch (e) {
            throw new Error(`can't parse key and token: ${e}`)
        }
    }

    serialize(): SerializedIssuerParams {
        const uidp = uint8ArrayToBase64(this.uidp)
        const descGq = { name: this.descGq.OID }
        const e = uint8ArrayToBase64(this.e)
        const g = this.g.map((g: GroupElement) => uint8ArrayToBase64(g.toByteArrayUnsigned()))
        const s = uint8ArrayToBase64(this.s)

        return { uidp, descGq, e, g, s }
    }

    static ParseIssuerParams(ipObj: SerializedIssuerParams): IssuerParams {
        try {
            if (!ipObj.uidp || !ipObj.descGq || !ipObj.e || !ipObj.g || !ipObj.s) {
                throw new Error('missing field')
            }

            const e = base64ToArray(ipObj.e)
            const numAttribs = e.length
            if (ipObj.g.length !== numAttribs + 2) {
                throw new Error(
                    `incorrect number of generators. ${ipObj.g.length} generators for ${ipObj.e.length} attributes`
                )
            }

            const uidp = base64ToUint8Array(ipObj.uidp)
            let descGq
            if (ipObj.descGq.name === L2048N256.OID) {
                descGq = L2048N256 // or new L2048N256Object()?
            } else if (ipObj.descGq.name === ECP256.OID) {
                descGq = ECP256 // Or new ECP256Object()
            } else if (ipObj.descGq.name === Curve25519.OID) {
                console.log(`loading curve25519`)
                descGq = Curve25519
            } else {
                throw new Error(`unknown group: ${ipObj.descGq.name}`)
            }
            const g = descGq.getPreGenGenerators(numAttribs)
            g[0] = descGq.getGq().createElementFromBytes(base64ToUint8Array(ipObj.g[0]))
            const s = base64ToUint8Array(ipObj.s)
            return new IssuerParams(uidp, descGq, g, e, s)
        } catch (e) {
            console.error(e)
            throw new Error(`can't parse issuer parameters: ${e}`)
        }
    }
}
