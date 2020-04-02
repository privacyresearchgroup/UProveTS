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
    descGq: Group
    e: number[]
    g: GroupElement[]
    s: Uint8Array
}

export interface IssuerParamsFunctions {
    isValid: () => boolean
    computeDigest: () => Uint8Array
    ParseFirstMessage: (fmObj: SerializedFirstMessage) => FirstMessage
    ParseThirdMessage: (fmObj: SerializedThirdMessage) => ThirdMessage
    ParseKeyAndToken: (ukatObj: SerializedKeyAndToken) => KeyAndToken
}

export interface SerializedGroupDescription {
    name: base64string
}

export type Group = any
export type GroupElement = any
export type Zq = any
export type ZqElement = any

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
    key: Uint8Array
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
    sc: base64string[] // TODO ???
}

export interface ThirdMessage {
    sr: ZqElement[]
}

// Prover

export type RandomNumberGenerator = any

export interface ProverData {
    rng: RandomNumberGenerator
    ip: IssuerParamsData & IssuerParamsFunctions
    Gq: Group
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
    s?: any
    gs: any
}

export interface Proof {
    D: base64string[]
    a: base64string
    r: base64string[]
    ap?: base64string
    Ps?: base64string
    tc?: base64string[]
    ta?: base64string[]
    tr?: base64string[]
}

export interface IEProof {
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
        ti: byte[], // TODO: is this Uint8Array?
        pi: byte[], // TODO: is this Uint8Array?
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
    ) => Proof
    verifiableEncrypt: (
        escrowParams: any,
        escrowPublicKey: any,
        token: any,
        additionalInfo: any,
        proof: any,
        commitmentPrivateValue: any,
        commitmentBytes: any,
        idAttribIndex: any,
        attribute: any
    ) => IEProof
}

// Hash

export type Integer = any // TODO: define this
export type Point = any // TODO: define this. EC point

export interface HashFunctions {
    updateByte: (b: byte) => void
    updateUint32: (size: number) => void
    updateBytes: (bs: Uint8Array) => void
    updateRawBytes: (bs: Uint8Array) => void
    updateNull: () => void
    updateListOfBytes: (list: byte[]) => void
    updateListOfByteArrays: (list: Uint8Array[]) => void
    updateListOfIndices: (list: number[]) => void
    updateListOfIntegers: (list: Integer[]) => void
    updatePoint: (point: Point) => void
    digest: () => Uint8Array
}
