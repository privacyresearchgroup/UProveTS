import { Hash } from './hash'
import { Attribute, ZqField, ZqElement } from './datatypes'

export function uint8ArrayToBase64(bytes: Uint8Array | number[]): string {
    if (!Array.isArray(bytes)) {
        bytes = Array.from(bytes)
    }
    return btoa(String.fromCharCode.apply(null, bytes))
}

export function base64ToArray(b64String: string): number[] {
    return atob(b64String)
        .split('')
        .map((c: string) => c.charCodeAt(0))
}

export function base64ToUint8Array(b64String): Uint8Array {
    return new Uint8Array(base64ToArray(b64String))
}

// Computes a*b+c mod q
export function ATimesBPlusCModQ(Zq: ZqField, a: ZqElement, b: ZqElement, c: ZqElement): ZqElement {
    const result = Zq.createElementFromInteger(0)
    Zq.multiply(a, b, result)
    Zq.add(result, c, result)
    return result
}

export function multiModExp(Gq, bases, exponents): any {
    if (bases.length !== exponents.length) {
        throw new Error('bases and exponents have different lengths')
    }
    const result = Gq.getIdentityElement()
    const temp = Gq.getIdentityElement()
    for (let i = 0; i < bases.length; i++) {
        Gq.modexp(bases[i], exponents[i], temp)
        Gq.multiply(result, temp, result)
    }

    return result
}

export function computeX(Zq, A, e): any {
    let x: any
    if (e === 1) {
        if (A === null) {
            x = 0
        } else {
            const H = new Hash()
            H.updateBytes(A)
            x = Zq.createModElementFromBytes(H.digest())
        }
    } else if (e === 0) {
        x = Zq.createModElementFromBytes(A)
    } else {
        throw new Error('invalid e value: ' + e)
    }
    return x
}

export function computeXArray(Zq, attributes: Attribute[], e): any[] {
    const n = attributes.length
    if (n !== e.length) {
        throw new Error('arguments must have the same length')
    }
    const x = new Array(n)
    for (let i = 0; i < n; i++) {
        x[i] = computeX(Zq, attributes[i], e[i])
    }
    return x
}

export function computeXt(Zq, ip, ti): any {
    const P = ip.computeDigest()
    const H = new Hash()
    H.updateByte(1)
    H.updateBytes(P)
    H.updateBytes(ti)
    return Zq.createModElementFromBytes(H.digest())
}

export function computeTokenId(token): Uint8Array {
    const hash = new Hash()
    hash.updateBytes(token.h.toByteArrayUnsigned())
    hash.updateBytes(token.szp.toByteArrayUnsigned())
    hash.updateBytes(token.scp.toByteArrayUnsigned())
    hash.updateBytes(token.srp.toByteArrayUnsigned())
    return hash.digest()
}

export function computeSigmaCPrime(Zq, h, pi, sigmaZPrime, sigmaAPrime, sigmaBPrime): any {
    const hash = new Hash()
    hash.updateBytes(h.toByteArrayUnsigned())
    hash.updateBytes(pi)
    hash.updateBytes(sigmaZPrime.toByteArrayUnsigned())
    hash.updateBytes(sigmaAPrime.toByteArrayUnsigned())
    hash.updateBytes(sigmaBPrime.toByteArrayUnsigned())
    return Zq.createModElementFromBytes(hash.digest())
}

export function generateChallenge(Zq, issuerParam, token, a, D, disclosedX, C, tildeC, tildeA, p, ap, Ps, m, md): any {
    // cp = H(uidt, a, <D>, <{xi}_in D>, C, <{tildeCi}_in C>, <{tildeAi}_in C>, p', ap, Ps, m)
    const uidt = computeTokenId(token)
    let hash = new Hash()
    hash.updateBytes(uidt)
    hash.updateBytes(a)
    hash.updateListOfIndices(D)
    hash.updateListOfIntegers(disclosedX)
    C ? hash.updateListOfIndices(C) : hash.updateNull()
    tildeC ? hash.updateListOfIntegers(tildeC) : hash.updateNull()
    tildeA ? hash.updateListOfByteArrays(tildeA) : hash.updateNull()
    hash.updateUint32(p) // p'
    ap ? hash.updateBytes(ap) : hash.updateNull()
    Ps ? hash.updateBytes(Ps.toByteArrayUnsigned()) : hash.updateNull()
    hash.updateBytes(m)
    const cp = hash.digest()

    // c = H(<cp, md>) --> Zq
    hash = new Hash()
    hash.updateUint32(2)
    hash.updateBytes(cp)
    md ? hash.updateBytes(md) : hash.updateNull()
    return Zq.createModElementFromBytes(hash.digest())
}

export function generateIdEscrowChallenge(
    Zq,
    UIDp,
    UIDt,
    H,
    CbBytes,
    E1,
    E2,
    CbPrime,
    E1Prime,
    E2Prime,
    additionalInfo
): any {
    // H(UID_p, UID_t, H, Cxb, E1, E2, Cxb', E1', E2', additionalInfo)
    const hash = new Hash()
    hash.updateBytes(UIDp)
    hash.updateBytes(UIDt)
    hash.updateBytes(H.toByteArrayUnsigned())
    hash.updateBytes(CbBytes)
    hash.updateBytes(E1.toByteArrayUnsigned())
    hash.updateBytes(E2.toByteArrayUnsigned())
    hash.updateBytes(CbPrime.toByteArrayUnsigned())
    hash.updateBytes(E1Prime.toByteArrayUnsigned())
    hash.updateBytes(E2Prime.toByteArrayUnsigned())
    hash.updateBytes(additionalInfo)
    return Zq.createModElementFromBytes(hash.digest())
}
