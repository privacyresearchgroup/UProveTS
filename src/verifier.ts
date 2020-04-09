import {
    IssuerParamsData,
    IssuerParamsFunctions,
    SerializedProof,
    MultiplicativeGroup,
    ZqField,
    Proof,
    GroupElement,
    ZqElement,
    UProveToken,
} from './datatypes'
import {
    base64ToUint8Array,
    base64ToArray,
    computeTokenId,
    generateChallenge,
    computeX,
    multiModExp,
    computeXt,
} from './utilities'
import { Hash } from './hash'
import cryptoMath from './msrcrypto/cryptoMath'

export class Verifier {
    ip: IssuerParamsData & IssuerParamsFunctions
    Gq: MultiplicativeGroup
    Zq: ZqField

    constructor(ip: IssuerParamsData & IssuerParamsFunctions) {
        this.ip = ip
        this.Gq = ip.descGq.getGq()
        this.Zq = ip.descGq.getZq()
    }

    parseProof(proof: SerializedProof): Proof {
        const D = proof.D.map(base64ToArray)
        const a = base64ToUint8Array(proof.a)
        const r = proof.r.map((b64: string) => this.Zq.createElementFromBytes(base64ToUint8Array(b64)))

        const ap = proof.ap ? base64ToUint8Array(proof.ap) : undefined
        const Ps = proof.Ps ? this.Gq.createElementFromBytes(base64ToUint8Array(proof.Ps)) : undefined

        let tc: GroupElement[] | undefined
        let ta: Uint8Array[] | undefined
        let tr: ZqElement[] | undefined
        if (proof.tc) {
            tc = proof.tc.map((b64: string) => this.Gq.createElementFromBytes(base64ToUint8Array(b64)))
            ta = proof.ta?.map((b64: string) => base64ToUint8Array(b64))
            tr = proof.tr?.map((b64: string) => this.Zq.createElementFromBytes(base64ToUint8Array(b64)))
        }

        return { D, a, r, ap, Ps, tc, ta, tr }
    }

    verifyTokenSignature(token: UProveToken): boolean {
        return false
    }

    /***
     * Note that the field`D` in `proof` contains the disclosed attributes.
     * The input `D` contains the indices of the disclosed attributes.
     */
    verify(proof: Proof, token: UProveToken, D: number[], C: number[], m: Uint8Array, md?: Uint8Array): boolean {
        const disclosedX: ZqElement[] = []
        for (let i = 0; i < proof.D.length; i++) {
            disclosedX[i] = computeX(this.Zq, proof.D[i], this.ip.e[D[i] - 1])
        }

        const c = generateChallenge(
            this.Zq,
            this.ip,
            token,
            proof.a,
            D,
            disclosedX,
            C,
            proof.tc,
            proof.ta,
            0, // scopeData?.p || 0
            proof.ap || null,
            proof.Ps || null,
            m,
            md
        )
        const minusC = this.Zq.createElementFromInteger(0)
        this.Zq.subtract(this.Zq.createElementFromInteger(0), c, minusC)

        const U: number[] = []
        const n = proof.D.length + proof.r.length - 1
        for (let i = 1; i <= n; ++i) {
            if (!D.find((d: number) => d === i)) {
                U.push(i)
            }
        }
        const uBases = U.map((u: number) => this.ip.g[u])
        uBases.unshift(token.h)
        const uPart = multiModExp(this.Gq, uBases, proof.r)

        console.log({ D, U })
        const dBases = D.map((d: number) => this.ip.g[d])
        const dPart = multiModExp(this.Gq, dBases, disclosedX)

        const xt = computeXt(this.Zq, this.ip, token.ti)
        const gtPart = this.Gq.getIdentityElement()

        this.Gq.modexp(this.ip.g[this.ip.t], xt, gtPart)
        this.Gq.multiply(gtPart, this.ip.g[0], gtPart)

        this.Gq.multiply(dPart, gtPart, dPart)
        this.Gq.modexp(dPart, minusC, dPart)

        const aInput = this.Gq.getIdentityElement()
        this.Gq.multiply(dPart, uPart, aInput)

        const hash = new Hash()
        console.log(`verifier`, {
            aInput: aInput.toByteArrayUnsigned(),
        })
        hash.updateBytes(aInput.toByteArrayUnsigned())
        const shouldBeA = hash.digest()

        console.log({ a: proof.a, shouldBeA })

        return cryptoMath.sequenceEqual(proof.a, shouldBeA)
    }
}
