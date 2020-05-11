import { PrivateKeyContainer } from '../../PrivateKeyContainer'
import { IssuerParams } from '../../issuerparams'
import { GroupElement, base64string, IDEscrowProof } from '../../datatypes'
import { uint8ArrayToBase64, base64ToUint8Array } from '../../utilities'

export interface AuditorParams {
    H: GroupElement
}

export interface SerializedAuditorParams {
    H: base64string
}

export class Auditor implements AuditorParams {
    H: GroupElement
    constructor(private _pkc: PrivateKeyContainer, private _ip: IssuerParams) {
        const Gq = _ip.descGq.getGq()
        const Zq = _ip.descGq.getZq()
        this.H = Gq.getIdentityElement()

        const x = Zq.createElementFromBytes(_pkc.getPrivateKeyBytes())
        Gq.modexp(_ip.g[0], x, this.H)
    }

    serialize(): SerializedAuditorParams {
        return {
            H: uint8ArrayToBase64(this.H.toByteArrayUnsigned()),
        }
    }

    decrypt(ieProof: IDEscrowProof): GroupElement {
        // TODO: verify info
        // TODO: verify is valid
        const Gq = this._ip.descGq.getGq()
        const Zq = this._ip.descGq.getZq()
        const Pb = Gq.getIdentityElement()

        const E1 = Gq.createElementFromBytes(base64ToUint8Array(ieProof.E1))
        const E2 = Gq.createElementFromBytes(base64ToUint8Array(ieProof.E2))

        const x = Zq.createElementFromBytes(this._pkc.getPrivateKeyBytes())
        const zero = Zq.createElementFromInteger(0)
        const minusX = Zq.createElementFromInteger(0)
        Zq.subtract(zero, x, minusX)

        Gq.modexp(E1, minusX, Pb)
        Gq.multiply(Pb, E2, Pb)

        return Pb
    }
}
