import { ZqField, RandomNumberGenerator, MultiplicativeGroup, IDEscrowProof } from '../datatypes'
import { IssuerParams } from '../issuerparams'
import { computeX, generateIdEscrowChallenge, computeTokenId, ATimesBPlusCModQ, uint8ArrayToBase64 } from '../utilities'

export class IDEscrowExtension {
    private _Gq: MultiplicativeGroup
    private _Zq: ZqField
    constructor(private _ip: IssuerParams, private _rng: RandomNumberGenerator) {
        this._Gq = _ip.descGq.getGq()
        this._Zq = _ip.descGq.getZq()
    }
    verifiableEncrypt(
        escrowPublicKey,
        token,
        additionalInfo,
        commitmentPrivateValue,
        commitmentBytes,
        idAttribIndex,
        attribute
    ): IDEscrowProof {
        const temp = this._Gq.getIdentityElement()
        const generator = this._ip.descGq.getGenerator()

        const r = this._rng.getRandomZqElement()

        const E1 = this._Gq.getIdentityElement()
        this._Gq.modexp(generator, r, E1) // E1 = g^r

        const xb = computeX(this._Zq, attribute, this._ip.e[idAttribIndex - 1])
        const E2 = this._Gq.getIdentityElement()
        this._Gq.modexp(generator, xb, E2) // E2 = g^xb
        this._Gq.modexp(escrowPublicKey.H, r, temp) // temp = H^r
        this._Gq.multiply(E2, temp, E2) // E2 = g^xb H^r

        const xbPrime = this._rng.getRandomZqElement()
        const obPrime = this._rng.getRandomZqElement()
        const CbPrime = this._Gq.getIdentityElement()
        this._Gq.modexp(generator, xbPrime, CbPrime) // C'b = g^xb'
        this._Gq.modexp(this._ip.g[1], obPrime, temp) // temp = g1^ob'
        this._Gq.multiply(CbPrime, temp, CbPrime) // C'b = g^xb' g1^ob'

        const rPrime = this._rng.getRandomZqElement()
        const E1Prime = this._Gq.getIdentityElement()
        this._Gq.modexp(generator, rPrime, E1Prime) // E1' = g^r'

        const E2Prime = this._Gq.getIdentityElement()
        this._Gq.modexp(generator, xbPrime, E2Prime) // E2' = g^xb'
        this._Gq.modexp(escrowPublicKey.H, rPrime, temp) // temp = H^r'
        this._Gq.multiply(E2Prime, temp, E2Prime) // E2' = g^xb' H^r'

        const c = generateIdEscrowChallenge(
            this._Zq,
            this._ip.uidp,
            computeTokenId(token),
            escrowPublicKey.H,
            commitmentBytes,
            E1,
            E2,
            CbPrime,
            E1Prime,
            E2Prime,
            additionalInfo
        )
        const cNegate = this._Zq.createElementFromInteger(0)
        this._Zq.subtract(this._Zq.createElementFromInteger(0), c, cNegate)

        const rxb = ATimesBPlusCModQ(this._Zq, cNegate, xb, xbPrime) // rXb = xb' - c.xb
        const rr = ATimesBPlusCModQ(this._Zq, cNegate, r, rPrime) // rr = r' - c.r
        const rob = ATimesBPlusCModQ(this._Zq, cNegate, commitmentPrivateValue, obPrime) // ro = ob' - c.ob

        const ieProof = {
            E1: uint8ArrayToBase64(E1.toByteArrayUnsigned()),
            E2: uint8ArrayToBase64(E2.toByteArrayUnsigned()),
            info: uint8ArrayToBase64(additionalInfo),
            ieproof: {
                c: uint8ArrayToBase64(c.toByteArrayUnsigned()),
                rXb: uint8ArrayToBase64(rxb.toByteArrayUnsigned()),
                rR: uint8ArrayToBase64(rr.toByteArrayUnsigned()),
                rOb: uint8ArrayToBase64(rob.toByteArrayUnsigned()),
            },
        }

        return ieProof
    }
}
