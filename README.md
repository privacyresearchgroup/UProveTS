# TypeScript library for the U-Prove Anonymous Credential system

This is a TypeScript SDK meant to allow developers to experiment with the [U-Prove](https://www.microsoft.com/en-us/research/project/u-prove/) anonymous credential system in web, mobile, and
backend applications. The mathematical core of this library is a direct port of Microsoft Research's [U-Prove Javascript SDK](https://www.microsoft.com/en-us/download/details.aspx?id=52491).

## Anonymous Credential Systems

The U-Prove protocol is an anonymous credential system. It allows a user who we'll call a _prover_ to interact with an _issuer_ to create cryptographic tokens with a set of attributes signed by the issuer. One might think of the issuer being a government issuing a passport, the user is the person getting the digital passport, and the attributes are all of the attributes of the user on the passport: name, birthdate, address, etc.

Once these tokens are created the user can use them to create a _presentation proof_ where he shows that he has a valid token (e.g. he has an authentic digital passport) and that certain facts are true about the attributes (e.g. "my name is Bob", "I am over 18 years old", "My photo hash is ...").

Putting these together, here's the sort of story we'd like to be able to tell:

- You visit your passport office, get a picture, verify your information, and then interact with them in an _issuance protocol_ to get a digital passport on your mobile phone.
- When asked for identification, the requestor can ask for certain bits of information: can I see your picture, name, state of residence, and a proof that your age is between 18 and 65?
- Your prover app can then provide a token from the issuer along with _provably correct_ answers to those questions.
- Meanwhile, the issuer does not need to be involved in this process and knows nothing about who you are interacting with.

This SDK makes it easy to implement all of these roles. We also have example implementations including:

- An AWS serverless issuer API
- A React Native mobile app that acts as a prover in an anonymous-credential based login system
- A React web app that acts as a verifier, receiving presentation proofs from the mobile app and using them as login and ID tokens, similar to how it might use an OIDC token.

## Differences from the Microsoft Research SDK

Significant changes include:

- Reorganization of code
- npm packaging
- Port to TypeScript
- Addition of components for issuers and verifiers with unit tests
- Use of jest for test automation
- Integration tests against a [sample issuer web service](https://github.com/privacyresearchgroup/uproveissuer)

## Goals

This project is meant to allow developers to quickly prototype applications using anonymous credentials so that they can understand data flow, secret management, and computational costs. It is not, at this time, aiming to be a production-ready library.

## Installation and Usage

To install with yarn, simply run

```
yarn add @privacyresearch/uprovets
```

For detailed example usage, look at [`__tests__/full-protocol.ts`](https://github.com/privacyresearchgroup/UProveTS/blob/master/src/__tests__/full-protocol.test.ts) and[`__tests__/integration-test.ts`](https://github.com/privacyresearchgroup/UProveTS/blob/master/src/__tests__/integration.test.ts). To execute and run the integration tests you will need to deploy an issuing server. A sample issuer is available [here](https://github.com/privacyresearchgroup/uproveissuer).

To run integration tests against an issuer service, you will need to add a file `src/__tests__/TestVectors/apidata.txt` with api configuration information in this form:

```
// api configuration data
uproveissuer = <UProve Issuer API Key>
url = <URL for issuer endpoint>
```

### Key Components

All users of the U-Prove system will need access to the issuer's public parameters. These are captured in the [`IssuerParams`](https://github.com/privacyresearchgroup/UProveTS/blob/master/src/issuerparams.ts) class which will typically be instantiated as follows

```
// The serialized issuer parameters will be obtained from a public registry or directly from the issuer
const serializedIssuerParams = {...}

const ip = IssuerParams.ParseIssuerParams(serializedIssuerParams)
```

An [`IssuerSession`](https://github.com/privacyresearchgroup/UProveTS/blob/master/src/issuer.ts) is used when implementing an issuer to take part in the U-Prove protocol. Creating an `IssuerSession` requires a `PrivateKeyContainer` which you will provide. Look at our [sample issuer web service](https://github.com/privacyresearchgroup/uproveissuer) for a detailed example.

A [`Prover`](https://github.com/privacyresearchgroup/UProveTS/blob/master/src/prover.ts) performs the functions of a prover in the U-Prove protocol - sending messages to and receiving messages from the issuer, generating tokens, and generating attribute presentation proofs. Here is an example, adapted from the unit tests, of a prover interacting with an issuer to generate tokens

```

    // Pseudocode - you will need to connect with your issuer and manage communication
    const firstMsg = issuerAPISession.getFirstMessage()

    // Prover parses it and creates the second message
    const proverFirstMsg = prover.ip.ParseFirstMessage(firstMsg)
    const secondMsg = prover.generateSecondMessage(
        1, // only generating one token
        attributes, // an array of arrays of numbers - use AttributeSet to encode typed data
        ti, // token information
        pi, // prover information, not seen by issuer
        null, // "external gamma" - this is a relic of the MSR SDK.  We compute gamma internally
        proverFirstMsg,
        true // skipTokenValidation
    )

    // Issuer creates third message
    const thirdMessage = issuerAPISession.sendSecondandGetThirdMessage()

    // Prover generates tokens
    const proverThirdMessage = protocolTest.prover.ip.ParseThirdMessage(thirdMessage)
    const keyAndBaseToken = protocolTest.prover.generateTokens(proverThirdMessage)
```

A prover also generates presentation proofs for relying parties or verifiers. In a presentation proof the prover reveals some attributes or assertions about attributes in a U-Prove token, along with a proof that the issuer token is valid and these assertions are true about the attributes the issuer saw when creating the token.

```
    const token: SerializedUProveToken = {
        ...keyAndBaseToken[0].token,
        uidp: uint8ArrayToBase64(ip.uidp),
        ti: uint8ArrayToBase64(ti),
        pi: uint8ArrayToBase64(pi),
    }
    const { key } = keyAndBaseToken[0]

    const ukat = protocolTest.ip.ParseKeyAndToken({ key, token })

    const proof = prover.generateProof(
        ukat,
        disclosed, // array of indexes of the attributes to disclose
        committed || [], // committed attributes used in some extensions
        message, // Uint8Array message for this proof
        messageD, // device message
        attributes, // cleartedxt attributes
        scopeData,
        commitmentPrivateValues
    )
```

Finally the [`Verifier`](https://github.com/privacyresearchgroup/UProveTS/blob/master/src/verifier.ts) is the third core component of this SDK. The verifier receives proofs from a prover and can validate the issuer signature ad validate the proof.

```

    const verifier = new Verifier(ip)
    const tokenIsValid = verifyTokenSignature(ukat.token)
    // Don't proceed if not valid!!!

    const parsedProof = verifier.parseProof(proof)

    const isValid = verifier.verify(parsedProof, ukat.token, disclosed, [], message, messageD)
    // Don't trust attributes if not valid!!!
```

## Contents

### Relationship with the MSR SDK

To help you understand the relationship with the Microsoft Research U-Prove SDK, here is a list of files organized by their relationship with the MSR code.

#### MSR SDK Components with Minimal Changes

The following files are ported directly from the Microsoft Research SDK with minimal changes for TypeScript compatibility:

- `msrcrypto/*.js`: These files are a partial port of the MSR Crypto library.
- `EcP256.ts`: A class wrapper for an elliptic curve group.
- `SubgroupL2048N256.ts`: A class wrapper for a finite cyclic group.

#### Files Substantially Derived from the MSR SDK

The core logic of the following files can be found almost verbatim in the MSR SDK, but the organization has been substantially changed.

- `hash.ts`
- `issuerparams.ts`
- `prover.ts`
- `utilities.ts`
- `testutilities/TestVectorRNG.ts`
- `testutilities/utilities.ts`
- `__tests__/hash.test.ts`
- `__tests__/prover.test.ts`

#### Files Forced by the MSR SDK

- `datatypes.ts`

#### New Additions

- `AttributeSet.ts`
- `PrivateKeyContainer.ts`
- `issuer.ts`
- `verifier.ts`
- `testutilities/ZqRNG.ts`
- `__tests__/full-protocol.test.ts`
- `__tests__/attribute.test.ts`
- `__tests__/integration.test.ts`

## License

This work is licensed under GPL v3 [https://www.gnu.org/licenses/gpl-3.0.en.html](https://www.gnu.org/licenses/gpl-3.0.en.html).

## Future Development

Short term development tasks are tracked using GitHub issues. Longer term, our goal is to complete implementation of U-Prove extensions for ID escrow, range proofs, and more. We also aim to create similar, compatible SDKs for other anonymous credential systems so that developers can easily experiment with these systems and compare alternatives.
