/*
 * Created April 2020
 *
 * Copyright (c) 2020 Privacy Research, LLC
 *
 *  Licensed under GPL v3 (https://www.gnu.org/licenses/gpl-3.0.en.html)
 *
 *  This code is a modification of Microsoft Research's U-Prove
 *  Javascript SDK (https://www.microsoft.com/en-us/download/details.aspx?id=52491). These
 *  portions are Copyright (c) Microsoft.  Changes to these portions include reorganization
 *  and addition of type information.
 */

import {
    ProverData,
    ProverFunctions,
    IssuerParamsFunctions,
    IssuerParamsData,
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
    SerializedProof,
    MultiplicativeGroup,
} from './datatypes'
import {
    computeSigmaCPrime,
    computeXArray,
    multiModExp,
    uint8ArrayToBase64,
    computeXt,
    base64ToUint8Array,
    computeX,
    generateChallenge,
    ATimesBPlusCModQ,
} from './utilities'
import { Hash } from './hash'
import { pseudoRandomBytes } from 'crypto'

export class Prover implements ProverData, ProverFunctions {
    rng: RandomNumberGenerator
    ip: IssuerParamsData & IssuerParamsFunctions
    Gq: MultiplicativeGroup
    Zq: Zq
    ti?: Uint8Array
    pi?: Uint8Array
    numberOfTokens = 0
    secondMsg: SerializedSecondMessage
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
    ): SerializedProof {
        if (!keyAndToken || !keyAndToken.key || !keyAndToken.token) {
            throw new Error('invalid key and token')
        }
        const n = this.ip.e.length
        const t = n + 1
        if (n !== attributes.length) {
            throw new Error('wrong number of attributes')
        }
        if (scopeData) {
            if (!scopeData.p || scopeData.p <= 0 || scopeData.p >= n) {
                throw new Error('invalid pseudonym index: ' + scopeData.p)
            }
            if (!scopeData.s && !scopeData.gs) {
                throw new Error('either scopeData.s or scopeData.gs must be set')
            }
        }
        if (D.find((n: number) => n === scopeData?.p)) {
            throw new Error(`It is an error to disclose the pseudonym attribute (attribute index: ${scopeData?.p})`)
        }
        if (D.find((n: number) => !!C.find((m: number) => n === m))) {
            console.log(`Cannot commit to a disclosed attribute.`, { D, C })
            throw new Error(`Cannot commit to a disclosed attribute.`)
        }

        const token = keyAndToken.token

        // make sure D and C arrays is sorted
        D.sort((a, b) => a - b) // from Crockford's "JavaScript: the good parts"
        if (C) {
            C.sort((a, b) => a - b) // from Crockford's "JavaScript: the good parts"
        }
        const x = new Array(n + 2)
        const size = 1 + (n - D.length)
        const disclosedA = new Array(D.length)
        const disclosedX = new Array(D.length)
        const w = new Array(size)
        const bases = new Array(size)
        w[0] = this.rng.getRandomZqElement()
        bases[0] = token.h
        let uIndex = 1
        let dIndex = 0
        let cIndex = 0
        let wpIndex = 0
        const commitmentData: any = {}
        if (C) {
            commitmentData.tildeC = new Array(C.length)
            commitmentData.tildeA = new Array(C.length)
            commitmentData.tildeO = new Array(C.length)
            commitmentData.tildeW = new Array(C.length)
        }
        for (let i = 1; i <= n; i++) {
            x[i] = computeX(this.Zq, attributes[i - 1], this.ip.e[i - 1])

            if (i === D[dIndex]) {
                // xi is disclosed
                disclosedX[dIndex] = x[i]
                disclosedA[dIndex] = uint8ArrayToBase64(attributes[i - 1])
                dIndex++
            } else {
                // xi is undisclosed
                w[uIndex] = this.rng.getRandomZqElement()
                bases[uIndex] = this.ip.g[i]
                if (scopeData && scopeData.p === i) {
                    wpIndex = uIndex
                }

                if (C && C.lastIndexOf(i) >= 0) {
                    // xi is committed
                    commitmentData.tildeO[cIndex] = this.rng.getRandomZqElement()
                    commitmentData.tildeW[cIndex] = this.rng.getRandomZqElement()
                    const cBases = [this.ip.descGq.getGenerator(), this.ip.g[1]]
                    commitmentData.tildeC[cIndex] = multiModExp(this.Gq, cBases, [x[i], commitmentData.tildeO[cIndex]])
                    const tildeAInput = multiModExp(this.Gq, cBases, [w[uIndex], commitmentData.tildeW[cIndex]])
                    const hash = new Hash()
                    hash.updateBytes(tildeAInput.toByteArrayUnsigned())
                    commitmentData.tildeA[cIndex] = hash.digest()
                    cIndex++
                }

                uIndex++
            }
        }
        x[t] = computeXt(this.Zq, this.ip, token.ti) // xt
        const aInput = multiModExp(this.Gq, bases, w)

        const hash = new Hash()
        hash.updateBytes(aInput.toByteArrayUnsigned())
        const a = hash.digest()
        let ap: Uint8Array | null = null
        let Ps: GroupElement | null = null

        if (scopeData) {
            let gs: GroupElement
            if (scopeData.gs) {
                gs = this.Gq.createElementFromBytes(scopeData.gs)
            } else {
                console.log(`generating scope element`, { scopeData })
                gs = this.ip.descGq.generateScopeElement(scopeData.s!)
            }
            const apInput = this.Gq.getIdentityElement()
            this.Gq.modexp(gs, w[wpIndex], apInput)

            const hash = new Hash()
            hash.updateBytes(apInput.toByteArrayUnsigned())
            ap = hash.digest()
            Ps = this.Gq.getIdentityElement()
            this.Gq.modexp(gs, x[scopeData.p], Ps)
        }

        const c = generateChallenge(
            this.Zq,
            this.ip,
            token,
            a,
            D,
            disclosedX,
            C,
            commitmentData.tildeC,
            commitmentData.tildeA,
            scopeData ? scopeData.p : 0,
            ap,
            Ps,
            m,
            md
        )

        const cNegate = this.Zq.createElementFromInteger(0)
        this.Zq.subtract(this.Zq.createElementFromInteger(0), c, cNegate)

        const r = new Array(size)
        r[0] = uint8ArrayToBase64(ATimesBPlusCModQ(this.Zq, c, keyAndToken.key, w[0]).toByteArrayUnsigned())
        dIndex = 0
        uIndex = 1
        for (let i = 1; i <= n; i++) {
            if (i === D[dIndex]) {
                // xi is disclosed
                dIndex++
            } else {
                // xi is undisclosed, compute a response
                r[uIndex] = uint8ArrayToBase64(
                    ATimesBPlusCModQ(this.Zq, cNegate, x[i], w[uIndex]).toByteArrayUnsigned()
                )
                uIndex++
            }
        }
        if (C) {
            commitmentData.tildeR = new Array(C.length)
            for (let i = 0; i < C.length; i++) {
                commitmentData.tildeR[i] = uint8ArrayToBase64(
                    ATimesBPlusCModQ(
                        this.Zq,
                        cNegate,
                        commitmentData.tildeO[i],
                        commitmentData.tildeW[i]
                    ).toByteArrayUnsigned()
                )
                commitmentData.tildeC[i] = uint8ArrayToBase64(commitmentData.tildeC[i].toByteArrayUnsigned())
                commitmentData.tildeA[i] = uint8ArrayToBase64(commitmentData.tildeA[i])
            }
        }

        const proof: SerializedProof = {
            D: disclosedA,
            a: uint8ArrayToBase64(a),
            r,
        }
        if (scopeData) {
            proof.ap = uint8ArrayToBase64(ap!)
            proof.Ps = uint8ArrayToBase64(Ps!.toByteArrayUnsigned())
        }
        if (C) {
            proof.tc = commitmentData.tildeC
            proof.ta = commitmentData.tildeA
            proof.tr = commitmentData.tildeR
        }
        if (commitmentPrivateValues && commitmentData.tildeO) {
            commitmentPrivateValues.tildeO = commitmentData.tildeO
        }
        return proof
    }

    computePseudonym(scopeData: ScopeData, attributes: Attribute[]): string {
        const n = this.ip.e.length
        const x = new Array(n + 2)

        for (let i = 1; i <= n; i++) {
            x[i] = computeX(this.Zq, attributes[i - 1], this.ip.e[i - 1])
        }

        let gs: GroupElement
        if (scopeData.gs) {
            gs = this.Gq.createElementFromBytes(scopeData.gs)
        } else {
            console.log(`generating scope element`, { scopeData })
            gs = this.ip.descGq.generateScopeElement(scopeData.s!)
        }
        const Ps = this.Gq.getIdentityElement()
        this.Gq.modexp(gs, x[scopeData.p], Ps)
        return uint8ArrayToBase64(Ps.toByteArrayUnsigned())
    }
}
