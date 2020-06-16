import { ZqField, ZqElement } from '../datatypes'
import { PrimeField, Residue, residuesEqual, MontgomeryLadder, residueAsBigInteger } from '@rolfe/pr-math'

export class ResidueWrapper implements ZqElement {
    residue: Residue
    m_digits: number[]
    m_group: ZqField
    constructor(group: ZqField, residue: Residue) {
        this.residue = residue
        this.m_digits = residue.digits
        this.m_group = group
    }
    equals(g: ZqElement): boolean {
        const reswrap = (g as any) as ResidueWrapper
        return residuesEqual(reswrap.residue, this.residue)
    }
    toByteArrayUnsigned(): number[] {
        return this.residue.toBytes()
    }
}

export class PrimeFieldWrapper implements ZqField {
    field: PrimeField
    m_modulus: number[]
    m_digitWidth: number
    constructor(field: PrimeField) {
        this.field = field
        this.m_modulus = field.modulus.digits
        this.m_digitWidth = this.m_modulus.length // nb. this is not the same as DIGIT_BITS == field.modulus.digitWidth
    }

    // TODO: this reduces to the least residue - will this cause problems?
    createElementFromBytes(bs: Uint8Array | number[]): ZqElement {
        const res = this.field.fromBytes(Array.from(bs))
        return new ResidueWrapper(this, res)
    }
    createElementFromDigits(ds: number[]): ZqElement {
        const res = this.field.fromDigits(ds)
        return new ResidueWrapper(this, res)
    }
    getIdentityElement(): ZqElement {
        return new ResidueWrapper(this, this.field.fromInteger(1))
    }
    createModElementFromBytes(bs: Uint8Array | number[]): ZqElement {
        return this.createElementFromBytes(bs)
    }

    createElementFromInteger(n: number): ZqElement {
        return new ResidueWrapper(this, this.field.fromInteger(n))
    }

    modexp(g: ZqElement, s: ZqElement, result: ZqElement): void {
        const gres = g as ResidueWrapper
        const sres = s as ResidueWrapper
        const resres = result as ResidueWrapper
        this.field.modExp(gres.residue, residueAsBigInteger(sres.residue), resres.residue)
    }
    multiply(a: ZqElement, b: ZqElement, result: ZqElement): void {
        const ares = a as ResidueWrapper
        const bres = b as ResidueWrapper
        const resres = result as ResidueWrapper
        this.field.multiply(ares.residue, bres.residue, resres.residue)
    }
    inverse(a: ZqElement, result: ZqElement): void {
        const ares = a as ResidueWrapper
        const resres = result as ResidueWrapper
        this.field.invert(ares.residue, resres.residue)
    }
    add(a: ZqElement, b: ZqElement, result: ZqElement): void {
        const ares = a as ResidueWrapper
        const bres = b as ResidueWrapper
        const resres = result as ResidueWrapper
        this.field.add(ares.residue, bres.residue, resres.residue)
    }
    subtract(a: ZqElement, b: ZqElement, result: ZqElement): void {
        const ares = a as ResidueWrapper
        const bres = b as ResidueWrapper
        const resres = result as ResidueWrapper
        this.field.subtract(ares.residue, bres.residue, resres.residue)
    }
}
