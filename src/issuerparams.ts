import {
    IssuerParamsData,
    IssuerParamsFunctions,
    Group,
    GroupElement,
    FirstMessage,
    SerializedFirstMessage,
    ThirdMessage,
    SerializedThirdMessage,
    KeyAndToken,
    SerializedKeyAndToken,
} from './datatypes'
import { Hash } from './hash'
import { base64ToUint8Array } from './utilities'

export class IssuerParams implements IssuerParamsData, IssuerParamsFunctions {
    uidp: Uint8Array
    descGq: Group
    e: number[]
    g: GroupElement[]
    s: Uint8Array
    P?: Uint8Array

    constructor(uidp: Uint8Array, descGq: Group, g: GroupElement[], e: number[], s: Uint8Array) {
        this.uidp = uidp
        this.descGq = descGq
        this.g = g
        this.e = e
        this.s = s
    }

    isValid(): boolean {
        return true
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
}
