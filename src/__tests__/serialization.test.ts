import Curve25519 from '../Curve25519'
import { base64ToUint8Array, bytesToBase64, residuesEqual } from '@rolfe/pr-math'
import cryptoMath from '../msrcrypto/cryptoMath'
import { PrimeFieldWrapper, ResidueWrapper } from '../pr-math-wrappers/prime-field'

test(`fromBytes matches fromBase64`, () => {
    const curve = Curve25519
    const b64 = 'AJ9ce9SOVHhIzneef/ndWPrFobQgNALyIPy9Uxj9OUAmB7ECb2/YVi/XIAcDoLCTx/WlQWPLJ8TNhMyvHBzwtA=='
    const eltFromB64 = curve.Gq.createElementFromBase64(b64)
    const eltFromBytes = curve.Gq.createElementFromBytes(base64ToUint8Array(b64))
    expect(eltFromB64.equals(eltFromBytes)).toBe(true)
    expect(cryptoMath.sequenceEqual(eltFromB64.toByteArrayUnsigned(), eltFromBytes.toByteArrayUnsigned()))
})

test(`prime field serialization`, () => {
    const Zq = Curve25519.getZq() as PrimeFieldWrapper
    const digits = [11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1]
    const a = Zq.createElementFromDigits(digits)
    const abytes = a.toByteArrayUnsigned()
    const ab64 = bytesToBase64(abytes)
    const b = Zq.createElementFromBytes(abytes)
    const c = Zq.field.fromBase64(ab64)

    expect(a.equals(b)).toBe(true)
    expect(residuesEqual((a as ResidueWrapper).residue, c)).toBe(true)
})
