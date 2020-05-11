import { MultiplicativeGroup, ZqField, IssuerParams, RandomNumberGenerator } from '../..'
import { IDEscrowProof, GroupElement } from '../../datatypes'
import { base64ToUint8Array, generateIdEscrowChallenge } from '../../utilities'
import { AuditorParams } from './Auditor'
import cryptoMath from '../../msrcrypto/cryptoMath'

export class IDEscrowVerifier {
    private _Gq: MultiplicativeGroup
    private _Zq: ZqField
    constructor(private _ip: IssuerParams, private _ap: AuditorParams) {
        this._Gq = _ip.descGq.getGq()
        this._Zq = _ip.descGq.getZq()
    }

    private _getGroupElement(): GroupElement {
        return this._ip.descGq.getGenerator()
    }

    verify(ieProof: IDEscrowProof, UIDt: Uint8Array, Cb: GroupElement): boolean {
        // these both validate that the point is really on the curve
        const E1 = this._Gq.createElementFromBytes(base64ToUint8Array(ieProof.E1))
        const E2 = this._Gq.createElementFromBytes(base64ToUint8Array(ieProof.E2))

        // TODO: verify these
        // note: rXb is r_b in the spec. rOb is r_o.
        const rXb = this._Zq.createElementFromBytes(base64ToUint8Array(ieProof.ieproof.rXb))
        const rR = this._Zq.createElementFromBytes(base64ToUint8Array(ieProof.ieproof.rR))
        const rOb = this._Zq.createElementFromBytes(base64ToUint8Array(ieProof.ieproof.rOb))
        const c = this._Zq.createElementFromBytes(base64ToUint8Array(ieProof.ieproof.c))

        const Cbpp = this._getGroupElement()
        const g1rO = this._getGroupElement()
        const grb = this._getGroupElement()

        const g = this._ip.descGq.getGenerator()
        const g1 = this._ip.g[1]

        // Compute Cb''
        this._Gq.modexp(Cb, c, Cbpp)
        this._Gq.modexp(g, rXb, grb)
        this._Gq.modexp(g1, rOb, g1rO)
        this._Gq.multiply(Cbpp, g1rO, Cbpp)
        this._Gq.multiply(Cbpp, grb, Cbpp)

        // compute E1''
        const E1pp = this._getGroupElement()
        const grr = this._getGroupElement()

        this._Gq.modexp(g, rR, grr)
        this._Gq.modexp(E1, c, E1pp)
        this._Gq.multiply(E1pp, grr, E1pp)

        // Compute E2''
        const E2pp = this._getGroupElement()
        const Hrr = this._getGroupElement()

        this._Gq.modexp(this._ap.H, rR, Hrr)
        this._Gq.modexp(E2, c, E2pp)
        this._Gq.multiply(E2pp, Hrr, E2pp)
        this._Gq.multiply(E2pp, grb, E2pp)

        const cp = generateIdEscrowChallenge(
            this._Zq,
            this._ip.uidp,
            UIDt,
            this._ap.H,
            Cb.toByteArrayUnsigned(), // ????
            E1,
            E2,
            Cbpp,
            E1pp,
            E2pp,
            base64ToUint8Array(ieProof.info)
        )

        return cryptoMath.sequenceEqual(c.toByteArrayUnsigned(), cp.toByteArrayUnsigned())
    }
}
