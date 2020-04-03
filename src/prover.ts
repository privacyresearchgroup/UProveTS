import {
    ProverData,
    ProverFunctions,
    IssuerParamsFunctions,
    IssuerParamsData,
    Group,
    Zq,
    RandomNumberGenerator,
    SerializedSecondMessage,
    Attribute,
    FirstMessage,
    SecondMessage,
    GroupElement,
    ZqElement,
    IssuanceState,
    SerializedBaseKeyAndToken,
    ThirdMessage,
    KeyAndToken,
    ScopeData,
    Proof,
    IEProof,
} from './datatypes'
import {
    computeSigmaCPrime,
    computeXArray,
    multiModExp,
    uint8ArrayToBase64,
    computeXt,
    base64ToUint8Array,
} from './utilities'

export class Prover implements ProverData, ProverFunctions {
    rng: RandomNumberGenerator
    ip: IssuerParamsData & IssuerParamsFunctions
    Gq: Group
    Zq: Zq
    ti?: Uint8Array
    pi?: Uint8Array
    numberOfTokens = 0
    secondMsg: SecondMessage
    h?: GroupElement[]
    alphaInverse?: ZqElement[]
    beta2?: ZqElement[]
    sigmaZPrime?: GroupElement[]
    sigmaCPrime?: ZqElement[]
    tokenValidationValue?: GroupElement[]

    constructor(rng: RandomNumberGenerator, ip: IssuerParamsData & IssuerParamsFunctions) {
        this.rng = rng
        this.ip = ip
        this.Gq = this.ip.descGq.getGq()
        this.Zq = this.ip.descGq.getZq()
        this.secondMsg = { sc: [] }
    }

    generateSecondMessage(
        numberOfTokens: number,
        attributes: Attribute[],
        ti: Uint8Array,
        pi: Uint8Array,
        externalGamma: number[] | null,
        firstMsg: FirstMessage,
        skipTokenValidation: boolean
    ): SerializedSecondMessage {
        const validateToken = skipTokenValidation ? false : true
        this.ti = ti
        this.pi = pi
        const generator = this.ip.descGq.getGenerator()

        this.numberOfTokens = numberOfTokens
        this.secondMsg = { sc: [] }
        this.h = new Array(this.numberOfTokens)
        this.alphaInverse = new Array(this.numberOfTokens)
        this.beta2 = new Array(this.numberOfTokens)
        this.sigmaZPrime = new Array(this.numberOfTokens)
        this.sigmaCPrime = new Array(this.numberOfTokens)
        if (validateToken) {
            this.tokenValidationValue = new Array(this.numberOfTokens)
        }

        // Prover input
        let gamma
        if (!externalGamma) {
            const x = computeXArray(this.Zq, attributes, this.ip.e)
            x.unshift(this.Zq.createElementFromInteger(1)) // exponent 1 for g0
            x.push(computeXt(this.Zq, this.ip, ti))
            // compute gamma = g0 * g1^x1 * ... * gn^xn * gt^xt
            gamma = multiModExp(this.Gq, this.ip.g, x)
        } else {
            gamma = this.Gq.createElementFromBytes(externalGamma)
        }
        const sigmaZ = firstMsg.sz
        for (let i = 0; i < this.numberOfTokens; i++) {
            // Prover precomputation
            const alpha = this.rng.getRandomZqElement()
            const beta1 = this.rng.getRandomZqElement()
            this.beta2[i] = this.rng.getRandomZqElement()

            // compute h = gamma^alpha
            this.h[i] = this.Gq.getIdentityElement()
            this.Gq.modexp(gamma, alpha, this.h[i])
            // compute alpha^-1
            this.alphaInverse[i] = this.Zq.createElementFromInteger(0)
            this.Zq.inverse(alpha, this.alphaInverse[i])

            const sigmaA = firstMsg.sa[i]
            const sigmaB = firstMsg.sb[i]

            // compute sigmaZPrime = sigmaZ ^ alpha
            this.sigmaZPrime[i] = this.Gq.getIdentityElement()
            this.Gq.modexp(sigmaZ, alpha, this.sigmaZPrime[i])

            // compute sigmaAPrime = g0^beta1 * g^beta2 * sigmaA
            let bases = new Array(this.ip.g[0], generator)
            let exponents = new Array(beta1, this.beta2[i])
            const sigmaAPrime = multiModExp(this.Gq, bases, exponents)
            this.Gq.multiply(sigmaAPrime, sigmaA, sigmaAPrime)

            // compute sigmaBPrime = sigmaZPrime^beta1 * h^beta2 * sigmaB^alpha
            bases = new Array(this.sigmaZPrime[i], this.h[i], sigmaB)
            exponents = new Array(beta1, this.beta2[i], alpha)
            const sigmaBPrime = multiModExp(this.Gq, bases, exponents)

            // compute sigmaCPrime = H(h, PI, sigmaZPrime, sigmaAPrime, sigmaBPrime) mod q
            this.sigmaCPrime[i] = computeSigmaCPrime(
                this.Zq,
                this.h[i],
                pi,
                this.sigmaZPrime[i],
                sigmaAPrime,
                sigmaBPrime
            )

            // compute sigmaC = sigmaCPrime + beta1
            const sigmaC = this.Zq.createElementFromInteger(0)
            this.Zq.add(this.sigmaCPrime[i], beta1, sigmaC)

            this.secondMsg.sc[i] = uint8ArrayToBase64(sigmaC.toByteArrayUnsigned())
            if (validateToken) {
                // value = sigmaA' . sigmaB' . (g0 . sigmaZ')^sigmaC'
                const value = this.Gq.getIdentityElement()
                const temp = this.Gq.getIdentityElement()
                this.Gq.multiply(sigmaAPrime, sigmaBPrime, value)
                this.Gq.multiply(this.ip.g[0], this.sigmaZPrime[i], temp)
                this.Gq.modexp(temp, this.sigmaCPrime[i], temp)
                this.Gq.multiply(value, temp, value)
                this.tokenValidationValue![i] = value
            }
        }

        return this.secondMsg
    }

    getIssuanceState(): IssuanceState {
        const h = new Array(this.numberOfTokens)
        const alphaInverse = new Array(this.numberOfTokens)
        const beta2 = new Array(this.numberOfTokens)
        const sigmaZPrime = new Array(this.numberOfTokens)
        const sigmaCPrime = new Array(this.numberOfTokens)
        let tokenValidationValue
        if (this.tokenValidationValue) {
            tokenValidationValue = new Array(this.numberOfTokens)
        }
        for (let i = 0; i < this.numberOfTokens; i++) {
            h[i] = uint8ArrayToBase64(this.h![i].toByteArrayUnsigned())
            alphaInverse[i] = uint8ArrayToBase64(this.alphaInverse![i].toByteArrayUnsigned())
            beta2[i] = uint8ArrayToBase64(this.beta2![i].toByteArrayUnsigned())
            sigmaZPrime[i] = uint8ArrayToBase64(this.sigmaZPrime![i].toByteArrayUnsigned())
            sigmaCPrime[i] = uint8ArrayToBase64(this.sigmaCPrime![i].toByteArrayUnsigned())
            if (this.tokenValidationValue) {
                tokenValidationValue[i] = uint8ArrayToBase64(this.tokenValidationValue[i].toByteArrayUnsigned())
            }
        }
        return { h, alphaInverse, beta2, sigmaZPrime, sigmaCPrime, tokenValidationValue }
    }

    // setIssuanceState: (state: import('./datatypes').IssuanceState) => void
    setIssuanceState(state: IssuanceState): void {
        if (!state || !state.h || !state.alphaInverse || !state.beta2 || !state.sigmaZPrime || !state.sigmaCPrime) {
            throw new Error('invalid state')
        }
        this.numberOfTokens = state.h.length
        this.h = new Array(this.numberOfTokens)
        this.alphaInverse = new Array(this.numberOfTokens)
        this.beta2 = new Array(this.numberOfTokens)
        this.sigmaZPrime = new Array(this.numberOfTokens)
        this.sigmaCPrime = new Array(this.numberOfTokens)
        if (state.tokenValidationValue) {
            this.tokenValidationValue = new Array(this.numberOfTokens)
        }
        for (let i = 0; i < this.numberOfTokens; i++) {
            this.h[i] = this.Gq.createElementFromBytes(base64ToUint8Array(state.h[i]))
            this.alphaInverse[i] = this.Zq.createElementFromBytes(base64ToUint8Array(state.alphaInverse[i]))
            this.beta2[i] = this.Zq.createElementFromBytes(base64ToUint8Array(state.beta2[i]))
            this.sigmaZPrime[i] = this.Gq.createElementFromBytes(base64ToUint8Array(state.sigmaZPrime[i]))
            this.sigmaCPrime[i] = this.Zq.createElementFromBytes(base64ToUint8Array(state.sigmaCPrime[i]))
            if (state.tokenValidationValue) {
                this.tokenValidationValue = this.tokenValidationValue || []
                this.tokenValidationValue![i] = this.Gq.createElementFromBytes(
                    base64ToUint8Array(state.tokenValidationValue[i])
                )
            }
        }
    }

    generateTokens(thirdMsg: ThirdMessage): SerializedBaseKeyAndToken[] {
        if (this.numberOfTokens !== thirdMsg.sr.length) {
            throw new Error('invalid length for message')
        }
        const keyAndTokens = new Array(this.numberOfTokens)
        for (let i = 0; i < this.numberOfTokens; i++) {
            const sigmaR = thirdMsg.sr[i]
            const sigmaRPrime = this.Zq.createElementFromInteger(0)
            this.Zq.add(sigmaR, this.beta2![i], sigmaRPrime)

            // validate the token
            if (this.tokenValidationValue) {
                const temp = this.Gq.getIdentityElement()
                this.Gq.multiply(this.ip.descGq.getGenerator(), this.h![i], temp)
                this.Gq.modexp(temp, sigmaRPrime, temp)
                if (!this.tokenValidationValue[i].equals(temp)) {
                    throw new Error(`invalid signature for token ${i}`)
                }
            }

            keyAndTokens[i] = {
                token: {
                    h: uint8ArrayToBase64(this.h![i].toByteArrayUnsigned()),
                    szp: uint8ArrayToBase64(this.sigmaZPrime![i].toByteArrayUnsigned()),
                    scp: uint8ArrayToBase64(this.sigmaCPrime![i].toByteArrayUnsigned()),
                    srp: uint8ArrayToBase64(sigmaRPrime.toByteArrayUnsigned()),
                },
                key: uint8ArrayToBase64(this.alphaInverse![i].toByteArrayUnsigned()),
            }
        }
        return keyAndTokens
    }

    generateProof(
        keyAndToken: KeyAndToken,
        D: number[],
        C: number[],
        m: Uint8Array,
        md: Uint8Array | null,
        attributes: Attribute[],
        scopeData: ScopeData | null,
        commitmentPrivateValues: any
    ): Proof | null {
        return null
    }
    verifiableEncrypt(
        escrowParams: any,
        escrowPublicKey: any,
        token: any,
        additionalInfo: any,
        proof: any,
        commitmentPrivateValue: any,
        commitmentBytes: any,
        idAttribIndex: any,
        attribute: any
    ): IEProof | null {
        return null
    }
}
