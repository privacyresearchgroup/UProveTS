import { ZqElement, ZqField } from '../datatypes'
import { DIGIT_NUM_BYTES } from '../msrcrypto/cryptoMath'

export class ZqRNG {
    constructor(private _Zq: ZqField, private _seed = 0) {
        // Note: can't seed Math.random.  Do something better later
    }

    getRandomZqElement(): ZqElement {
        const numBytes = DIGIT_NUM_BYTES * this._Zq.m_digitWidth
        const bytes = Array(numBytes)
        for (let i = 0; i < numBytes; ++i) {
            bytes[i] = Math.floor(256 * Math.random())
        }
        return this._Zq.createModElementFromBytes(new Uint8Array(bytes))
    }
}
