import msrcryptoSha256 from './msrcrypto/sha256'
import cryptoECC from './msrcrypto/cryptoECC'
import { HashFunctions, Integer, Point, byte } from './datatypes'

const Uint8ArrayToArray = (uint8Array: Uint8Array | number[]) => Array.from(uint8Array)

export class Hash implements HashFunctions {
    sha256: any

    constructor() {
        this.sha256 = msrcryptoSha256.sha256
    }

    updateByte(b: byte): void {
        this.sha256.process([b])
    }

    updateUint32(size: number): void {
        const buffer = [size >> 24, size >> 16, size >> 8, size]
        this.sha256.process(buffer)
    }

    updateBytes(bytes: Uint8Array | number[]): void {
        this.updateUint32(bytes.length)
        this.sha256.process(Uint8ArrayToArray(bytes))
    }

    updateRawBytes(bytes: Uint8Array): void {
        this.sha256.process(Uint8ArrayToArray(bytes))
    }

    updateRawArray(ns: number[]): void {
        this.sha256.process(ns)
    }

    updateNull(): void {
        this.updateUint32(0)
    }

    updateListOfBytes(list: number[]): void {
        this.updateUint32(list.length)
        // tslint:disable-next-line: prefer-for-of
        for (let i = 0; i < list.length; i++) {
            this.updateByte(list[i])
        }
    }

    updateListOfByteArrays(list: Uint8Array[]): void {
        this.updateUint32(list.length)
        // tslint:disable-next-line: prefer-for-of
        for (let i = 0; i < list.length; i++) {
            this.updateBytes(list[i])
        }
    }

    updateListOfIndices(list: number[]): void {
        this.updateUint32(list.length)
        // tslint:disable-next-line: prefer-for-of
        for (let i = 0; i < list.length; i++) {
            this.updateUint32(list[i])
        }
    }

    updateListOfIntegers(list: Integer[]): void {
        this.updateUint32(list.length)
        // tslint:disable-next-line: prefer-for-of
        for (let i = 0; i < list.length; i++) {
            this.updateBytes(list[i].toByteArrayUnsigned())
        }
    }

    updatePoint(point: Point): void {
        this.updateBytes((cryptoECC as any).sec1EncodingFp().encodePoint(point))
    }

    digest(): Uint8Array {
        return new Uint8Array(this.sha256.finish())
    }
}
