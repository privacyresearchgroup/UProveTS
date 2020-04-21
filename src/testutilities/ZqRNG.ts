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
