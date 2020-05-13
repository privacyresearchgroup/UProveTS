/*
 * Created April 2020
 *
 * Copyright (c) 2020 Privacy Research, LLC
 *
 *  Licensed under GPL v3 (https://www.gnu.org/licenses/gpl-3.0.en.html)
 *
 */

export type base64string = string

// IssuerParams

export interface SerializedIssuerParams {
    uidp: base64string
    descGq: SerializedGroupDescription
    e: base64string
    g: base64string[] // really only used for g[0]
    s: base64string
}

export interface IssuerParamsData {
    uidp: Uint8Array
    descGq: DLGroup
    e: number[]
    g: GroupElement[]
    s: Uint8Array
    readonly t: number
}

export interface IssuerParamsFunctions {
    isValid: () => boolean
    computeDigest: () => Uint8Array
    ParseFirstMessage: (fmObj: SerializedFirstMessage) => FirstMessage
    ParseThirdMessage: (fmObj: SerializedThirdMessage) => ThirdMessage
    ParseKeyAndToken: (ukatObj: SerializedKeyAndToken) => KeyAndToken
    serialize: () => SerializedIssuerParams
}

export interface SerializedGroupDescription {
    name: string
}

export type Zq = ZqField

export interface GroupElement {
    equals: (g: GroupElement) => boolean
    copyTo: (source: GroupElement, destination: GroupElement) => void
    clone: () => GroupElement
    toByteArrayUnsigned: () => Uint8Array
}

export interface ECGroupElement extends GroupElement {
    copy: (destination: ECGroupElement) => void
    x: number[] // digits of x coordinate
    y: number[] // digits of y coordinate
    z?: number[] // digits of z coordinate
    isInMontgomeryForm: boolean
    isInfinity: boolean
    isAffine: boolean
    curve: any
}

export function isECGroupElement(g: GroupElement): g is ECGroupElement {
    return !!(g as any).curve
}

export interface ZqElement {
    m_digits: number[]
    m_group: Zq
    equals: (g: ZqElement) => boolean
    toByteArrayUnsigned: () => number[]
}

export interface MultiplicativeGroup {
    createElementFromBytes: (bs: Uint8Array | number[]) => GroupElement
    getIdentityElement: () => GroupElement
    modexp: (g: GroupElement, s: ZqElement, result: GroupElement) => void
    multiply: (a: GroupElement, b: GroupElement, result: GroupElement) => void
}

export interface DLGroup {
    OID: string
    getGq: () => MultiplicativeGroup
    getZq: () => ZqField
    updateHash: (h: HashFunctions) => void
    getGenerator: () => GroupElement
    getPreGenGenerators: (n: number) => GroupElement[]
    computeVerifiablyRandomElement: (context: Uint8Array, index: byte) => GroupElement
    generateScopeElement: (s: Uint8Array) => GroupElement
}

export interface GroupDescription {
    getGq: () => MultiplicativeGroup
    getZq: () => Zq
    updateHash: (h: HashFunctions) => void
    getGenerator: () => GroupElement
    getPreGenGenerators: (n: number) => GroupElement[]
}

export interface ZqField {
    m_modulus: number[]
    m_digitWidth: number // length of element in digits
    createElementFromBytes: (bs: Uint8Array | number[]) => ZqElement
    createElementFromDigits: (ds: number[]) => ZqElement
    getIdentityElement: () => ZqElement
    createModElementFromBytes: (bs: Uint8Array) => ZqElement
    createElementFromInteger: (n: number) => ZqElement
    modexp: (g: ZqElement, s: ZqElement, result: ZqElement) => void
    multiply: (a: ZqElement, b: ZqElement, result: ZqElement) => void
    inverse: (a: ZqElement, result: ZqElement) => void
    add: (a: ZqElement, b: ZqElement, result: ZqElement) => void
    subtract: (a: ZqElement, b: ZqElement, result: ZqElement) => void
}

// UProve Token

export interface SerializedBaseToken {
    h: base64string
    szp: base64string
    scp: base64string
    srp: base64string
}

export interface SerializedUProveToken extends SerializedBaseToken {
    uidp: base64string
    ti: base64string
    pi: base64string
}

export interface UProveToken {
    uidp: Uint8Array
    h: GroupElement
    ti?: Uint8Array | null
    pi?: Uint8Array | null
    szp: GroupElement
    scp: ZqElement
    srp: ZqElement
    d: boolean
}

export interface SerializedBaseKeyAndToken {
    token: SerializedBaseToken
    key: base64string
}

export interface SerializedKeyAndToken {
    token: SerializedUProveToken
    key: base64string
}

export interface KeyAndToken {
    token: UProveToken
    key: ZqElement
}

// Messages

export interface SerializedFirstMessage {
    sz: base64string
    sa: base64string[]
    sb: base64string[] // sa.length === sb.length
}

export interface SerializedSecondMessage {
    sc: base64string[]
}

export interface SerializedThirdMessage {
    sr: base64string[]
}

export interface FirstMessage {
    sz: GroupElement
    sa: GroupElement[]
    sb: GroupElement[]
}

export interface SecondMessage {
    sc: ZqElement[]
}

export interface ThirdMessage {
    sr: ZqElement[]
}

// Prover

export interface RandomNumberGenerator {
    getRandomZqElement: () => ZqElement
}

export interface ProverData {
    rng: RandomNumberGenerator
    ip: IssuerParamsData & IssuerParamsFunctions
    Gq: MultiplicativeGroup
    Zq: Zq
}

export interface IssuanceState {
    h: base64string[]
    alphaInverse: base64string[]
    beta2: base64string[]
    sigmaZPrime: base64string[]
    sigmaCPrime: base64string[]
    tokenValidationValue?: base64string[]
}

export interface ScopeData {
    p: number
    s?: Uint8Array
    gs?: Uint8Array
}

export interface SerializedProof {
    D: base64string[]
    a: base64string
    r: base64string[]
    ap?: base64string
    Ps?: base64string
    tc?: base64string[]
    ta?: base64string[]
    tr?: base64string[]
}

export type Digest = Uint8Array
export interface Proof {
    D: Attribute[]
    a: Digest
    r: ZqElement[]
    ap?: Digest
    Ps?: GroupElement
    tc?: GroupElement[]
    ta?: Digest[]
    tr?: ZqElement[]
}

export interface IDEscrowProof {
    E1: base64string
    E2: base64string
    info: base64string
    ieproof: {
        c: base64string
        rXb: base64string
        rR: base64string
        rOb: base64string
    }
}

export type byte = number
export type Attribute = byte[]

export interface ProverFunctions {
    generateSecondMessage: (
        numberOfTokens: number,
        attributes: Attribute[],
        ti: Uint8Array,
        pi: Uint8Array,
        externalGamma: byte[] | null,
        firstMsg: FirstMessage,
        skipTokenValidation: boolean
    ) => SerializedSecondMessage
    getIssuanceState: () => IssuanceState
    setIssuanceState: (state: IssuanceState) => void
    generateTokens: (thirdMsg: ThirdMessage) => SerializedBaseKeyAndToken[]
    generateProof: (
        keyAndToken: KeyAndToken,
        D: number[],
        C: number[],
        m: Uint8Array,
        md: Uint8Array | null,
        attributes: Attribute[],
        scopeData: ScopeData | null,
        commitmentPrivateValues: any
    ) => SerializedProof
}

// Hash

export type Integer = any // TODO: define this
export type Point = any // TODO: define this. EC point

export interface HashFunctions {
    updateByte: (b: byte) => void
    updateUint32: (size: number) => void
    updateBytes: (bs: Uint8Array | number[]) => void
    updateRawBytes: (bs: Uint8Array) => void
    updateNull: () => void
    updateListOfBytes: (list: byte[]) => void
    updateListOfByteArrays: (list: Uint8Array[]) => void
    updateListOfIndices: (list: number[]) => void
    updateListOfIntegers: (list: Integer[]) => void
    updatePoint: (point: Point) => void
    digest: () => Uint8Array
}
