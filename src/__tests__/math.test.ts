import { simpleCurve25519 } from '@privacyresearch/pr-math'
import { ECGroupElement, ZqElement, ScopeData } from '..'
import cryptoMath from '../msrcrypto/cryptoMath'
import ECP256 from '../EcP256'
import cryptoECC from '../msrcrypto/cryptoECC'

const chatty = false
test('generate scope elt', () => {
    const scopeData: ScopeData = { p: 1, s: Uint8Array.from([90, 11, 117, 103, 103, 108, 97]) }
    const gs = ECP256.generateScopeElement(scopeData.s!)
    // console.log(gs.toByteArrayUnsigned())
})
test('math check', () => {
    const group = ECP256
    const Gq = group.Gq

    const Zq = group.Zq
    const gs = Gq.createElementFromBytes([
        4,
        172,
        54,
        7,
        8,
        32,
        188,
        111,
        86,
        211,
        238,
        0,
        76,
        130,
        90,
        98,
        255,
        229,
        155,
        214,
        79,
        118,
        30,
        189,
        180,
        91,
        189,
        101,
        76,
        105,
        161,
        159,
        43,
        29,
        214,
        8,
        117,
        165,
        147,
        206,
        225,
        141,
        153,
        176,
        252,
        252,
        191,
        245,
        74,
        228,
        16,
        32,
        248,
        111,
        5,
        214,
        136,
        236,
        249,
        31,
        248,
        181,
        156,
        67,
        84,
    ])
    const cxpfor6 = [
        12479020,
        14683843,
        7297631,
        4293744,
        13690075,
        14608046,
        4451239,
        9512638,
        14416312,
        970944,
        60410,
    ]
    const cxpfor7 = [5265037, 6639165, 5393163, 8039823, 12019111, 14246585, 16377923, 11098077, 5634219, 6725430, 4942]

    const xp = Zq.createElementFromBytes([7])
    // const c = Zq.createElementFromBytes([5, 11])

    // const xp = Zq.createElementFromBytes([73, 150, 2, 210])
    const c = Zq.createElementFromBytes(
        Uint8Array.from([
            39,
            84,
            87,
            205,
            117,
            121,
            254,
            244,
            24,
            49,
            31,
            181,
            252,
            155,
            250,
            123,
            199,
            205,
            123,
            121,
            224,
            64,
            189,
            103,
            228,
            101,
            80,
            2,
            117,
            245,
            17,
            178,
        ])
    )

    const untyped = gs as any
    // console.log(`is valid curve point: ${untyped.validate()}`)

    const p256 = cryptoECC.createP256()
    const g = ECP256.getGenerator()
    const moddigits = [...Zq.m_modulus]
    moddigits[0] = moddigits[0] - 1
    const modminusone = Zq.createElementFromDigits(moddigits)
    if (chatty) {
        // console.log({ modminusone: modminusone.m_digits, mod: Zq.m_modulus, gqorder: p256.order, p256 })
    }
    const gs2modminusone = Gq.getIdentityElement()
    Gq.modexp(gs, modminusone, gs2modminusone)

    const gs2modulus = Gq.getIdentityElement()
    Gq.multiply(gs2modminusone, gs, gs2modulus)

    const cxp = Zq.createElementFromInteger(0)
    Zq.multiply(xp, c, cxp)
    // cxp = Zq.createElementFromBytes(cxp.toByteArrayUnsigned())

    const Ps = Gq.getIdentityElement()
    Gq.modexp(gs.clone(), xp, Ps)

    const gs2cxp = Gq.getIdentityElement()
    Gq.modexp(gs.clone(), cxp, gs2cxp)

    const Ps2c = Gq.getIdentityElement()
    Gq.modexp(Ps, c, Ps2c)

    const Ps2cxp = Gq.getIdentityElement()
    Gq.modexp(Ps, cxp, Ps2cxp)

    // const Ps2cXgs2cxp = Gq.getIdentityElement()
    // Gq.multiply(Ps2c, gs2cxp, Ps2cXgs2cxp)

    const gs2c = Gq.getIdentityElement()
    Gq.modexp(gs.clone(), c, gs2c)

    const gs2c2xp = Gq.getIdentityElement()
    Gq.modexp(gs2c, xp, gs2c2xp)

    if (chatty) {
        // console.log('MATH TEST', {
        // Ps2cXgs2cxp: Ps2cXgs2cxp.toByteArrayUnsigned(),
        //     gs: pointRep(gs as ECGroupElement),
        //     Ps: pointRep(Ps as ECGroupElement),
        //     xp: modPointRep(xp),
        //     c: modPointRep(c),
        //     cxp: modPointRep(cxp),
        //     gs2modulus: pointRep(gs2modulus as ECGroupElement),
        //     Ps2cxp: pointRep(Ps2cxp as ECGroupElement),
        //     gs2cxp: pointRep(gs2cxp as ECGroupElement),
        //     Ps2c: pointRep(Ps2c as ECGroupElement),
        //     gs2c2xp: pointRep(gs2c2xp as ECGroupElement),
        //     modulus: cxp.m_group.m_modulus,
        // })
    }
    expect(cryptoMath.sequenceEqual(Ps2c.toByteArrayUnsigned(), gs2cxp.toByteArrayUnsigned())).toBeTruthy()
})

function pointRep(g: ECGroupElement): any {
    return {
        x: g.x,
        y: g.y,
        z: g.z,
        isInMontgomeryForm: g.isInMontgomeryForm,
        isAffine: g.isAffine,
        isInfinity: g.isInfinity,
    }
}

function modPointRep(n: ZqElement): any {
    return {
        digits: n.m_digits,
    }
}

test(`curve25519 test`, () => {
    // quick sanity check of imported curve
    // order of generator: 2^252 + 27742317777372353535851937790883648493
    // 7237005577332262213973186563042994240857116359379907606001950938285454250989
    // 0x1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED
    const gOrd = 'EAAAAAAAAAAAAAAAAAAAABTe+d6i95zWWBJjGlz10+0='

    const curve = simpleCurve25519
    const ord = curve.field.fromBase64(gOrd)
    const ordMinusOne = curve.field.fromInteger(1)
    curve.field.negate(ordMinusOne, ordMinusOne)
    curve.field.add(ord, ordMinusOne, ordMinusOne)
    const g = curve.generator.clone()
    const q = curve.generator.clone()
    curve.scalarMultiply(ordMinusOne, g, q)
    // console.log({ ord: ord.digits, gx: g.x.digits, qx: q.x.digits, gy: g.y.digits, qy: q.y.digits })
    expect(cryptoMath.sequenceEqual(g.x.digits, q.x.digits)).toBeTruthy()
    expect(cryptoMath.sequenceEqual(g.y.digits, q.y.digits)).toBeFalsy()
})
