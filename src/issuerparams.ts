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
import { base64ToUint8Array, base64ToArray } from './utilities'
import L2048N256 from './SubgroupL2048N256'
import ECP256 from './EcP256'

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

    static ParseIssuerParams(ipObj: SerializedIssuerParams): IssuerParams {
        try {
            if (!ipObj.uidp || !ipObj.descGq || !ipObj.e || !ipObj.g || !ipObj.s) {
                throw new Error('missing field')
            }

            const uidp = base64ToUint8Array(ipObj.uidp)
            let descGq
            if (ipObj.descGq.name === L2048N256.OID) {
                descGq = L2048N256 // or new L2048N256Object()?
            } else if (ipObj.descGq.name === ECP256.OID) {
                descGq = ECP256 // Or new ECP256Object()
            } else {
                throw new Error(`unknown group: ${ipObj.descGq.name}`)
            }
            const e = base64ToArray(ipObj.e)
            const numAttribs = e.length
            const g = descGq.getPreGenGenerators(numAttribs)
            g[0] = descGq.getGq().createElementFromBytes(base64ToUint8Array(ipObj.g[0]))
            const s = base64ToUint8Array(ipObj.s)
            return new IssuerParams(uidp, descGq, g, e, s)
        } catch (e) {
            throw new Error(`can't parse issuer parameters: ${e}`)
        }
    }
}
