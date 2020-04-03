import { Zq, ZqElement } from '../datatypes'
import { readVectorElement } from '../__tests__/issuance.test'

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
                  readVectorElement(Zq, vectors, 'alpha'),
                  readVectorElement(Zq, vectors, 'beta1'),
                  readVectorElement(Zq, vectors, 'beta2'),
                  readVectorElement(Zq, vectors, 'w0'),
                  readVectorElement(Zq, vectors, 'w1'),
                  readVectorElement(Zq, vectors, 'w3'),
                  readVectorElement(Zq, vectors, 'w4'),
              ]
            : [
                  // full version
                  readVectorElement(Zq, vectors, 'alpha'),
                  readVectorElement(Zq, vectors, 'beta1'),
                  readVectorElement(Zq, vectors, 'beta2'),
                  readVectorElement(Zq, vectors, 'w0'),
                  readVectorElement(Zq, vectors, 'w1'),
                  readVectorElement(Zq, vectors, 'tildeO1'),
                  readVectorElement(Zq, vectors, 'tildeW1'),
                  readVectorElement(Zq, vectors, 'w3'),
                  readVectorElement(Zq, vectors, 'w4'),
                  readVectorElement(Zq, vectors, 'tildeO4'),
                  readVectorElement(Zq, vectors, 'tildeW4'),
                  readVectorElement(Zq, vectors, 'ie_r'),
                  readVectorElement(Zq, vectors, 'ie_xbPrime'),
                  readVectorElement(Zq, vectors, 'ie_obPrime'),
                  readVectorElement(Zq, vectors, 'ie_rPrime'),
              ]
    }

    getRandomZqElement(): ZqElement {
        this.index++
        return this.values[this.index]
    }
}
