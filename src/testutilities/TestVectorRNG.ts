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

import { Zq, ZqElement } from '../datatypes'
import { readVectorZqElement } from './utilities'

export class TestVectorRNG {
    values: ZqElement[]
    index: number

    static create(
        lite: boolean,
        Zq: Zq,
        vectors: {
            [k: string]: any
        }
    ): TestVectorRNG {
        return new TestVectorRNG(lite, Zq, vectors)
    }

    constructor(
        lite: boolean,
        Zq: Zq,
        vectors: {
            [k: string]: any
        }
    ) {
        this.index = -1
        this.values = lite
            ? [
                  // lite version
                  readVectorZqElement(Zq, vectors, 'alpha'),
                  readVectorZqElement(Zq, vectors, 'beta1'),
                  readVectorZqElement(Zq, vectors, 'beta2'),
                  readVectorZqElement(Zq, vectors, 'w0'),
                  readVectorZqElement(Zq, vectors, 'w1'),
                  readVectorZqElement(Zq, vectors, 'w3'),
                  readVectorZqElement(Zq, vectors, 'w4'),
              ]
            : [
                  // full version
                  readVectorZqElement(Zq, vectors, 'alpha'),
                  readVectorZqElement(Zq, vectors, 'beta1'),
                  readVectorZqElement(Zq, vectors, 'beta2'),
                  readVectorZqElement(Zq, vectors, 'w0'),
                  readVectorZqElement(Zq, vectors, 'w1'),
                  readVectorZqElement(Zq, vectors, 'tildeO1'),
                  readVectorZqElement(Zq, vectors, 'tildeW1'),
                  readVectorZqElement(Zq, vectors, 'w3'),
                  readVectorZqElement(Zq, vectors, 'w4'),
                  readVectorZqElement(Zq, vectors, 'tildeO4'),
                  readVectorZqElement(Zq, vectors, 'tildeW4'),
                  readVectorZqElement(Zq, vectors, 'ie_r'),
                  readVectorZqElement(Zq, vectors, 'ie_xbPrime'),
                  readVectorZqElement(Zq, vectors, 'ie_obPrime'),
                  readVectorZqElement(Zq, vectors, 'ie_rPrime'),
              ]
    }

    getRandomZqElement(): ZqElement {
        this.index++
        return this.values[this.index]
    }
}
