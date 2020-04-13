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
