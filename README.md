# TypeScript library for the U-Prove Anonymous Credential system
This is a TypeScript SDK meant to allow developers to experiment with the [U-Prove](https://www.microsoft.com/en-us/research/project/u-prove/) anonymous credential system in web, mobile, and
backend appliations.  The mathematical core of this library is a direct port of Microsoft Research's [U-Prove Javascript SDK](https://www.microsoft.com/en-us/download/details.aspx?id=52491). 

## Differences from the Microsoft Research SDK
Significant changes include:
* Reorganization of code
* npm packaging
* Port to TypeScript
* Addition of components for issuers and verifiers with unit tests
* Use of jest for test automation
* Integration tests against a [sample issuer web service](https://github.com/rolfeschmidt/uproveissuer)

## Goals
This project is meant to allow developers to quickly prototype applications using anonymous credentials so that they can understand data flow, secret management, and computational costs.  It is not, at this time, aiming to be a production-ready library.

## Installation and Usage
To install with yarn, simply run
```
yarn install @rolfe/uprovets
```
For detailed example usage, look at [`__tests__/full-protocol.ts`](https://github.com/rolfeschmidt/UProveTS/blob/master/src/__tests__/full-protocol.test.ts) and[`__tests__/integration-test.ts`](https://github.com/rolfeschmidt/UProveTS/blob/master/src/__tests__/integration.test.ts).  To execute and run the integration tests you will need to deploy an issuing server. A sample issuer is available [here](https://github.com/rolfeschmidt/uproveissuer).

## Contents
### Relationship with the MSR SDK
To help you understand the relationship with the Microsoft Research U-Prove SDK, here is a list of files organized by their relationship with the MSR code.

#### MSR SDK Components with Minimal Changes
The following files are ported directly from the Microsoft Research SDK with minimal changes for TypeScript compatibility:
* `msrcrypto/*.js`: These files are a partial port of the MSR Crypto library.
* `EcP256.ts`: A class wrapper for an elliptic curve group.
* `SubgroupL2048N256.ts`: A class wrapper for a finite cyclic group.

#### Files Substantially Derived from the MSR SDK
The core logic of the following files can be found almost verbatim in the MSR SDK, but the organization has been substantially changed.
* `hash.ts`
* `issuerparams.ts`
* `prover.ts`
* `utilities.ts`
* `testutilities/TestVectorRNG.ts`
* `testutilities/utilities.ts`
* `__tests__/hash.test.ts`
* `__tests__/prover.test.ts`


#### Files Forced by the MSR SDK
* `datatypes.ts`

#### New Additions
* `AttributeSet.ts`
* `PrivateKeyContainer.ts`
* `issuer.ts`
* `verifier.ts`
* `testutilities/ZqRNG.ts`
* `__tests__/full-protocol.test.ts`
* `__tests__/attribute.test.ts`
* `__tests__/integration.test.ts`

## License
This work is licensed under GPL v3 [https://www.gnu.org/licenses/gpl-3.0.en.html](https://www.gnu.org/licenses/gpl-3.0.en.html).

## Future Development
Short term development tasks are tracked using GitHube issues.  Longer term, our goal is to complete implementation of U-Prove extensions for ID escrow, range proofs, and more.  We also aim to create similar, compatible SDKs for other anonymous credential systems so that developers can easily experiment with these systems and compare alternatives.
