// *********************************************************
//
//    Original file: Copyright (c) Microsoft. All rights reserved.
//    Modifications for TypeScript conversion: Copyright (c) Privacy Research, LLC
//
//    Modifications licensed under GPL v3 (https://www.gnu.org/licenses/gpl-3.0.en.html)
//
//    Original licensed under the Apache License, Version 2.0 (the "License");
//    you may not use this file except in compliance with the License.
//    You may obtain a copy of the License at
//
//        http://www.apache.org/licenses/LICENSE-2.0
//
//    Unless required by applicable law or agreed to in writing, software
//    distributed under the License is distributed on an "AS IS" BASIS,
//    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//    See the License for the specific language governing permissions and
//    limitations under the License.
//
// *********************************************************

// U-Prove ECP256 Recommended Parameters.
// See http://www.microsoft.com/uprove for details.

// tslint:disable: number-literal-format
import {
    simpleCurve25519 as curve25519,
    MontgomeryCurve,
    MontgomeryCurvePoint,
    SimpleMontgomeryCurvePoint,
    Residue,
    MontgomeryLadder,
    copyResidueTo,
    simpleCurve25519,
    digitsToBytes,
    base64ToArray,
    StandardPrimeField,
    residuesEqual,
    cloneResidue,
    sqrt,
} from '@rolfe/pr-math'

import cryptoMath, { DIGIT_BITS } from './msrcrypto/cryptoMath'
import {
    HashFunctions,
    MultiplicativeGroup,
    DLGroup,
    GroupElement,
    ECGroupElement,
    ZqElement,
    byte,
    ZqField,
} from './datatypes'
import { Hash } from './hash'
import { ResidueWrapper, PrimeFieldWrapper } from './pr-math-wrappers/prime-field'

export class MontgomeryPointWrapper implements GroupElement {
    montPoint: MontgomeryCurvePoint
    constructor(montPoint: MontgomeryCurvePoint) {
        this.montPoint = montPoint
    }

    equals(g: GroupElement): boolean {
        if (!isWrappedMontgomeryPoint(g)) {
            return false
        }
        const { x, y, z } = g.montPoint
        // TODO: check projective equality???
        return (
            cryptoMath.sequenceEqual(x.digits, this.montPoint.x.digits) &&
            cryptoMath.sequenceEqual(y.digits, this.montPoint.x.digits) &&
            cryptoMath.sequenceEqual(z.digits, this.montPoint.z.digits)
        )
    }
    copyTo(source: GroupElement, destination: GroupElement): void {
        if (isWrappedMontgomeryPoint(source) && isWrappedMontgomeryPoint(destination)) {
            destination.montPoint = source.montPoint.clone() as MontgomeryCurvePoint
        } else {
            throw new Error('Cannot copy wrapped montgomery point to different point type')
        }
    }
    clone(): GroupElement {
        return new MontgomeryPointWrapper(this.montPoint.clone() as MontgomeryCurvePoint)
    }
    toByteArrayUnsigned(): Uint8Array {
        return Uint8Array.from(this.montPoint.toBytes())
    }
}

function prMathResidueToZqElement(Zq: ZqField, res: Residue): ZqElement {
    if (
        !(
            res.group.modulus.digitWidth === DIGIT_BITS &&
            cryptoMath.sequenceEqual(Zq.m_modulus, res.group.modulus.digits)
        )
    ) {
        throw new Error('incompatible fields')
    }
    return Zq.createElementFromDigits(res.digits)
}

export function isWrappedMontgomeryPoint(g: GroupElement): g is MontgomeryPointWrapper {
    return !!(g as any).montPoint
}

// This one is for the order of the group
// order of generator: 2^252 + 27742317777372353535851937790883648493
// 7237005577332262213973186563042994240857116359379907606001950938285454250989
// 0x1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED
const gOrdb64 = 'EAAAAAAAAAAAAAAAAAAAABTe+d6i95zWWBJjGlz10+0='
const gOrd = simpleCurve25519.field.fromBase64(gOrdb64)
const orderfield = new StandardPrimeField({ digits: gOrd.digits, digitWidth: DIGIT_BITS })

export class Montgomery25519Group implements MultiplicativeGroup {
    curve: MontgomeryCurve
    ladder: MontgomeryLadder
    ecOperator: any
    Zq = new PrimeFieldWrapper(orderfield)

    constructor(curve: MontgomeryCurve) {
        this.curve = curve
        this.ladder = new MontgomeryLadder(curve)
    }
    // allocates an element to store some computation results
    getIdentityElement(): MontgomeryPointWrapper {
        // return the point at infinity
        return new MontgomeryPointWrapper(this.curve.zero.clone() as MontgomeryCurvePoint)
    }

    // creates an element from the serialized bytes
    createElementFromBytes(bytes: Uint8Array | number[]): MontgomeryPointWrapper {
        const result = new MontgomeryPointWrapper(this.curve.fromBytes(Array.from(bytes)) as MontgomeryCurvePoint)

        return result
    }
    createElementFromBase64(b64: string): MontgomeryPointWrapper {
        return new MontgomeryPointWrapper(this.curve.fromBase64(b64))
    }

    createPoint(x: Uint8Array | number[], y: Uint8Array | number[]): MontgomeryPointWrapper {
        const { field } = curve25519
        const xres = field.fromBytes(Array.from(x))
        const yres = field.fromBytes(Array.from(y))
        const zres = field.fromInteger(1)

        const mp = new SimpleMontgomeryCurvePoint(curve25519, xres, yres, zres)
        const result = new MontgomeryPointWrapper(mp)
        return result
    }

    // computes result = [scalar] point.
    modexp(point: GroupElement, scalar: ZqElement, result: GroupElement): void {
        const wpoint = point as MontgomeryPointWrapper
        const wresult = result as MontgomeryPointWrapper
        if (wpoint.montPoint.curve !== this.curve || wresult.montPoint.curve !== this.curve) {
            console.error(`wrong curve`, { curve: this.curve, result, point })
            throw new Error('exponentiating wrong type of GroupElement on elliptic curve')
        }

        const wscalar = scalar as ResidueWrapper
        if (wscalar.residue.group !== this.Zq.field && wscalar.residue.group !== this.curve.field.indexGroup) {
            console.error({ wscalar, curve: this.curve })
            throw new Error(
                'curve25519 scalars must be wrapped pr-math objects with group order p-1 or order of subgroup'
            )
        }

        // scalar multiplication
        const rslt = this.ladder.scalarMultiply(wscalar.residue, wpoint.montPoint)

        copyResidueTo(rslt.x, wresult.montPoint.x)
        copyResidueTo(rslt.y, wresult.montPoint.y)
        copyResidueTo(rslt.z, wresult.montPoint.z)
    }

    // computes result = a + b
    multiply(a: GroupElement, b: GroupElement, result: GroupElement): void {
        const wa = a as MontgomeryPointWrapper
        const wb = b as MontgomeryPointWrapper
        const wresult = result as MontgomeryPointWrapper
        if (
            wa.montPoint.curve !== this.curve ||
            wb.montPoint.curve !== this.curve ||
            wresult.montPoint.curve !== this.curve
        ) {
            console.error(`wrong curve`, { curve: this.curve, result, a, b })
            throw new Error('multiplying wrong type of GroupElement on elliptic curve')
        }
        this.curve.add(wa.montPoint, wb.montPoint, wresult.montPoint)
    }

    getZq(): ZqField {
        return this.Zq
    }
}

class Curve25519Object implements DLGroup {
    // number of pregenerated generators
    n = 50
    // gt index
    t = this.n + 1

    generatorsBase64 = [
        'AJ9ce9SOVHhIzneef/ndWPrFobQgNALyIPy9Uxj9OUAmB7ECb2/YVi/XIAcDoLCTx/WlQWPLJ8TNhMyvHBzwtA==',
        'cJQw0nL707wK0zP53eOtDLGUQMC0VC6gPMEjip8e4Fk5hiXV8CwGEYhaUwjjSco3VwSZiNJkglxkDF9Q+OQZbg==',
        'JjJz2ukKfYUyWrhScSa+5SwMRN0hDkfk6RyaCmKHQDEzl30J2I0RTWSxXF6GiKsjXxnUdxzIjo6aIL+O24cnxg==',
        'LnGZl4j8pWV5LZItC+D551oulv2FXpFOWZs6NPg4klchZm55JwQX4uSlkaZK95gI6mgYR2UpBe21gQ6EC0md2A==',
        'I5+DNyPrGwTxddmJuoh4p5Tgr8XsNaxV0GpP5HvkUfg4K8TNsHjmh9UVjvdlmVIZpLE+gjx2SC+5XyuP3S7/xA==',
        'NRFWVDNHKnkFGte1neU3u5AMY9v2uyaUrLlgSRcsei84ALWY3Ijc47upbjl3+upo25irzJ69AdfCrYc+nvFOww==',
        'Lu+X3070RiBXejVPKHyuM/KQ1ydfxLUbCwPdzt4VwaAtJ0dfJmB48iZUo/C2jVtES5QauWy0XW/XnPtCN01y0Q==',
        'be/rb+HIgaSJ2nB9yji9opmTeUBcoaP6aUygN3fLkzwLwYWemBMskgf1or/BxtXZ0sIsfUE2wx/j3nK4WFXCnw==',
        'YQNwxinocnan2/7Iw67XvEFQ0mYtZmeYZMOvaZ//OnUJKXVLoze3qVwzCfKiYgCeblkucN2fMUk+NJ8cj2UnvA==',
        'HCyGG12XmRw4MapSU5yF3Qz2221yBH1hPgiPqyY+wLwNEIoRXnsoPuJCyJuOV/kTHAtencM9gpKZhtJd/SWwkg==',
        'Rr5KbApwpVoIU4KndIxRIAHUrT1uy9QSYixWDp/yCzoj2J4Qg7VP3WHRiAYiISKn4GkRi/Vy+QyiRPDSM6QPiQ==',
        'HOHAU8t+te+3LRbnWG7n6msLf2+aiA6oP1qqCk7stXkSjGZaGCypC71JJtkFKtsuiGB9CsTq9/MV+QY8gw9Grw==',
        'ExCYU6Cs+Jcpzpo896UYI0f4uz92WA0y0/1gI1Fdj2USjCFol3279w+iIa4mY5j06OwGvbxBDDVz3zhYbdvPLQ==',
        'HeBZCUZESLFvpgEziqcMHWoQcHVtkRp0kfWNSdMF5oM2ikcf75/6eTFHL+3tIYAthTH4TpMEt9LyWCEu/oMSOQ==',
        'AxF7yHsRInrjwQSLcT6IgxC5+tWG0UXxZU+4jWhrYpYii5mHTYSS/51g6eT+quzbRN7VNrzKN1qqkukXDu7bCQ==',
        'U5D0ln3IlN9ln6bHbjjiGARwIrYOGBmOqgctIf/g6Ug4xf0aWMGYoLvAhnxAkuX4h8mMnp5Nfv2U+ckU2lG3OQ==',
        'fk2lcamrCN/Rll6uSj/1JtgYleCXny3dVEhDe2QUCyw1LyvHW0eVvPv3lg6h3UlbR+HrCm37TCm/9RYquCgh+Q==',
        'Cy03UVT5ASex4UyI6zHlfM9PactM4HzCbJigICj9wws/RyU6nUfASyeRhRKNPKLse4l5TgVD4aR3b/Gmszfo2Q==',
        'bwxkYmXzOY5WcYc3xAAZkjRmfJfGMjVsCZzLFLYYmTkApipD1U3ny54IvJCvZcli4mZ+Ic1cr3RXjDO7gmqD3w==',
        'D/ihEvkDM1AsqNQpC80DD5IbySxRXBdMxunXToBTeSQ989HaC0a0xwVdIRmyJ4S5+iZHmm07VviaW+Zk1hdS8A==',
        'XAKaidYagp7ax51O+yTnFs54Ui7zzvUlcIx4K2+gFc4QPp3xI7epMKF3oanxHfpLLJJie4/ey51Kn3UxfOmO9w==',
        'RsD1sr6ZuAfUaer7ICV/o3M+iSOmDJGqY9xIOxuFZYAkpDn0LmHJFS30jalMNy6L8yqJqanDC6COQywZdcCQaQ==',
        'fgjx8FyZ0EvwIWB+UZa62C+wmY2FjFyjXC4l9mvj0cYFifeZEV+VFztVmBf0Av5vttE9DSHEz8HPyVax4RrNzA==',
        'ftZhnVohERIfGw172QIRq6xyFvEHF87x04SHIlPUqd4OamznD+85jIzt24undne/FoFf2h40zUQp5xWzMcB0/g==',
        'EMmMG9QP5iuoT3kscffbsuQuJy/Z0wjt/CpKLtkPAdo1xq1cJ0RReMOT/Mw43KF+H036q7Txyw2HELb4fYOcPA==',
        'AGwq32FE3G4SM9B260UI4wlVnqt825EIoZTZpyP5ErMaRm3CSIoicHLvaSbi5XrMiHZ9o1n3ivBUPHaVI6etGA==',
        'D0uBh/si2EdnXPzjj0zmA15HiPZtV0xl9QTfZdKUoxw9BPP1t1V1vQ1v4gNDawFL3lCC5J3K86yyhjmSpaQevA==',
        'OzuRSaS0/kdvxgwYvv66hlC9DEJjLyX61vW5spo0U/kGLz86J6iQjfyCGydbvIw9BcCr2QHXRRAX6omyCsQTGA==',
        'AAtJG7g8pLh7JuSXmIMNidPSjcN9xGxM6x1sEvQxmQsbSvCjW5MNdn4TzDQXygiXSVdxPuZiT0oHdzBu16817g==',
        'DSO8R+eVX4lTs5Z8oQ1PJNbcrINcgpJoivXzLY5YeJoI7RL/rzpmE4ivCd/IzCxuRzVEjYtYqcV6agjPBQ8bIQ==',
        'D/Y3CxVoQ+2VSvzy0pCnfNcCI3egThGbSUeBOI0/Of4iaBvG8OC7Yjb+TPE8D2CILDDxq14oIaJpTivazHr+2g==',
        'J5A34gi/DJdw+DqCChaDP7NMfbom9UwM3xC9JtQhfkI77f2mO7L3rNjPGdK2+ZzVEyFQaKeRFYH0/p3I0qVxKQ==',
        'FpjE/J+of6dGTWJAer9ZFMllWY5PmCv5EuPpgQn3pHoz92d2ohq0M4TydRriL/Ds2nTUwHmn9uTeHqCYMb8FTw==',
        'FBVUYDLvNxdZ3+ITWKWtlWxkeHb+gasFDQuYGs7LnzoOFA+D1CbTJLyf7iIs4FXuHOZJLr6KGi7kLPwHdcslOw==',
        'Wa6WxBcQ6/0+ZRsjwgaNMzFWmkcoBnhqVhNqDS1jmHo91mS/o6RDf064OMEIcxHpxaCPWT48GqpzIe0dET1pjw==',
        'LBhRU8nZqu+72Vp0Bb5pyR/CMlhAVH691mzlh0KAsRgPA3zwoCM7cDxb/3JK0Y3XGPf8Z5mzo6xKYFG9+/tVsA==',
        'J62joJv7kK0+O414OC6pc6xwsjbSGLSTCkl1ODt8zeoIF8WTjhJnqdeukmEp+Sl5jbQLRjn6XCCaweq557PcNg==',
        'CL8t8+NM4+aRPRoDdQxzEpc7jhymddL36k7P0tEqDnEFa7xKQwnQG5DZuvxJdPWUV+frHDhBL3ePIecwh5PHew==',
        'Cb6rEpSBwVSx33YG36XCc8fpoTMneAc3HJ/tXYaq/KUjEZcaT0znBmeivc5gHJ3vyO7Xq+1R4tL/TXXtgtnqHg==',
        'IZxS1aeC1LY2WdnT+vulbxD85WFid3m2ArjlmSkMbkYs1CqismJp9G2hFh7wvPehKb9g98K5Q+kerMYcHsTDug==',
        'S7tKT5/CIx4pwc7z7DZytlBAZHgXDAmYaHbsmQ5y5vIJAZg+/5231KDJ57jAYqP3maEkExnAI67iDsxETPbAbA==',
        'Ulbp0QGM5Vku92ohiTsioJqyJZFc6X14ubDAFKrHuZECii4jsiYlsB98+2n0Ns+ItflFHT2xI5Irjn85m3WD8w==',
        'GsXEmvugqSp3maTEeKHV7786OwCHvnyA9fAu7WStK2QqZYoymY8FU3nFFD2E/wmlXyXnMR89CFSlt4OZzDqjyw==',
        'Do0xhMCeNBP2TDW57YSCXn09DrdZqs4H53mtucFcGnEVzowJEbVWX9uk810ACvVYRIzCRLZiaMc0ZqU+0A0Weg==',
        'cVEumGULEh1teaoMxMXSCxW9XxYj05GMBV95L9CUSS0PbKcD2iRHtyK5RQKZ0b1wb27SXIjK2zYdHdv55IgQ2A==',
        'MMw8Tdb+JFRfHDBsnsuL/fQ9a/jtl50DYl4fVjHtEqcNNEQH0ZysY8zqj+jXxyNKVvTFi09uBjYb6H4BmUKoHA==',
        'S7IcV2uEuRSVVmF5UfuztIcIojHnfW7IjxDP6izBGw0jdNGO/xiSYVg+BpsMA0rKz19q+8Th/4XfklqLlBWG5Q==',
        'Kra1Le+rmLz3fnxHC08T1dT3CMEqtT969lge68J3XBA+X4syn3UH9KgEYo5XLvmr7UllcFZDK/jINTju5fP5xQ==',
        'NfN3rGAWcICT+NLYYxWPnmIGhIQtJe+te07s0/Hf/JoUv/mw5NSOeHlDQ1XLrzicYL/Eu87Jdx1gXQAtxK2Isg==',
        'XfQeKMgYNDRM7y7bbs9JvTCZ5ZSw88cuyo/P8bkbK4kFIy3yiYLjryhkk7JKrUxA/ZQ9K2t1muwLqvR2/qpLHg==',
        'Otr6eGuDtx0OkEG2zrzOXQTlkW3kjIRmsGRyeyogXAUA+oDERVQp7XSW59hHm9JPcue2AeP4ntQxz291p+FH1g==',
    ]

    // recommended parameters

    Gq = new Montgomery25519Group(simpleCurve25519)
    getGq(): Montgomery25519Group {
        return this.Gq
    }

    Zp = new PrimeFieldWrapper(simpleCurve25519.field)
    // cryptoMath.IntegerGroup(Uint8Array.from(cryptoMath.digitsToBytes(this.p256.order)))
    getZp(): ZqField {
        return this.Zp
    }

    // This one is for the order of the group
    // order of generator: 2^252 + 27742317777372353535851937790883648493
    // 7237005577332262213973186563042994240857116359379907606001950938285454250989
    // 0x1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED
    gOrdb64 = 'EAAAAAAAAAAAAAAAAAAAABTe+d6i95zWWBJjGlz10+0='
    gOrd = simpleCurve25519.field.fromBase64(this.gOrdb64)
    orderfield = new StandardPrimeField({ digits: this.gOrd.digits, digitWidth: DIGIT_BITS })
    Zq = this.Gq.Zq
    // cryptoMath.IntegerGroup(Uint8Array.from(cryptoMath.digitsToBytes(this.p256.order)))
    getZq(): ZqField {
        return this.Zq
    }

    getGenerator(): MontgomeryPointWrapper {
        return new MontgomeryPointWrapper(simpleCurve25519.generator.clone())
    }

    // update the hash with the group values
    // hash   - UProve.Hash          - the hash function to update
    updateHash(hash: HashFunctions): void {
        // H(p,a,b,g,q,1)
        hash.updateListOfBytes(digitsToBytes(simpleCurve25519.field.modulus.digits))
        hash.updateListOfBytes(digitsToBytes(simpleCurve25519.weierstrassA.digits))
        hash.updateListOfBytes(digitsToBytes(simpleCurve25519.weierstrassB.digits))
        hash.updateListOfBytes(simpleCurve25519.generator.toBytes())

        hash.updateListOfBytes(base64ToArray(this.gOrdb64))
        hash.updateListOfBytes([8]) // cofactor is 8
    }

    // returns an array of n + 2 pre-generated generators: 1, g1, ..., gn, gt.
    // The first element (g0) is set to 1 and must be replaced by caller with
    // an Issuer-specific value.
    getPreGenGenerators(n: number): any {
        const gen = new Array(n + 2)
        gen[0] = this.Gq.getIdentityElement() // to be replaced by caller
        for (let i = 1; i <= n; i++) {
            // g1, ..., gn
            gen[i] = this.Gq.createElementFromBase64(this.generatorsBase64[i - 1])
        }
        gen[n + 1] = this.Gq.createElementFromBase64(this.generatorsBase64[this.t - 1])
        return gen
    }

    getX(input: Uint8Array | number[], counter: number): ResidueWrapper {
        const numIterations = 1 // for P-256/SHA-256, ratio is 1
        const H = new Hash()
        const zeroByte = 0x30 // ascii value for 0
        H.updateRawBytes(Uint8Array.from(input))
        // Hash([index, count, iteration]). index always 0 for generation scope, iteration always 0 for P-256/SHA-256
        H.updateRawArray([zeroByte, zeroByte + counter, zeroByte])
        const digest = H.digest()
        return new ResidueWrapper(this.Zp, simpleCurve25519.field.fromBytes(Array.from(digest)))
    }

    private f(x: Residue): Residue {
        const field = simpleCurve25519.field

        const rhs = field.fromInteger(0)

        field.add(simpleCurve25519.A, x, rhs)
        field.multiply(rhs, x, rhs)
        field.add(rhs, field.one, rhs)
        field.multiply(rhs, x, rhs)
        field.multiply(rhs, simpleCurve25519.BInv, rhs)
        return rhs
    }

    computeVerifiablyRandomElement(context: Uint8Array | number[]): MontgomeryPointWrapper {
        const { field } = simpleCurve25519

        let x: ResidueWrapper
        let y: Residue | null = null
        let count = 0

        const { Zp, Zq } = this
        while (y === null) {
            x = this.getX(context, count)
            // z = x^3 + ax^2 + x mod p
            const z = new ResidueWrapper(Zp, this.f(x.residue))

            if (residuesEqual(z.residue, field.zero)) {
                y = cloneResidue(z.residue)
            } else {
                // y = Sqrt(z)
                // i.e. y such that y^2 === z mod p
                // or null if no such element exists
                y = sqrt(z.residue)
            }
            count++
        }
        // validate
        const y2 = Zp.createElementFromInteger(1)
        let yelt = new ResidueWrapper(Zp, y)
        Zp.multiply(yelt, yelt, y2)
        // take the smallest sqrt of y
        const negY = field.fromInteger(0)
        field.negate(y, negY)

        if (cryptoMath.compareDigits(y.digits, negY.digits) >= 0) {
            yelt = new ResidueWrapper(Zp, negY)
        }

        return this.Gq.createPoint(x!.toByteArrayUnsigned(), yelt.toByteArrayUnsigned())
    }

    generateScopeElement(s: Uint8Array): MontgomeryPointWrapper {
        if (!s) {
            throw new Error('invalid scope')
        }

        return this.computeVerifiablyRandomElement(s)
    }

    computeGeneratorForIndex(i: number): MontgomeryPointWrapper {
        const inputstr = `U-Prove Reccommended Parameters Profile${this.OID}${i}`
        const input = inputstr.split('').map((c: string) => c.charCodeAt(0))
        return this.computeVerifiablyRandomElement(input)
    }

    OID = 'curve25519'
}

const Curve25519 = new Curve25519Object()
export default Curve25519
