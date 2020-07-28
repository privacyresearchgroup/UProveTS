import Curve25519, { MontgomeryPointWrapper } from '../Curve25519'
import { residuesEqual, base64ToArray } from '@rolfe/pr-math'
import msrcryptoUtilities from '../msrcrypto/utilities'
import { uint8ArrayToBase64, base64ToUint8Array } from '../utilities'
import {
    PrivateKeyContainer,
    InMemoryPrivateKeyContainer,
    AttributeSet,
    ScopeData,
    SerializedUProveToken,
    Verifier,
} from '..'
import { IssuerParams } from '../issuerparams'
import { ZqRNG } from '../testutilities/ZqRNG'
import { Prover } from '../prover'
import { IssuerSession } from '../issuer'

export const performanceTimer = performance || Date // performance not supported on Safari

// const attributes = AttributeSet.fromJSON({
//     sub: '406baf85-24af-44bd-ba23-1e38a955796d',
//     name: 'Surullinen Weil',
//     given_name: '',
//     family_name: '',
//     middle_name: '',
//     preferred_username: 'surly',
//     profile: '',
//     picture: 'hello.jpg',
//     website: '',
//     email: 'sw@example.com',
//     email_verified: false,
//     gender: '',
//     birthdate: '2020/01/01',
//     zoneinfo: '',
//     locale: '',
//     phone_number: '+1-888-123-4567',
//     phone_number_verified: false,
//     address: '',
//     updated_at: Date.now(),
// })

// const attributes = AttributeSet.fromJSON({
//     sub: '406baf85-24af-44bd-ba23-1e38a955796d',
//     username: 'Surullinen Weil',
//     email: 'sw@example.com',
//     avatar: 'https://news.artnet.com/app/news-upload/2017/08/NO45-1024x1024.jpg',
//     phoneNumber: '800-867-5309',
// })

const attributes = AttributeSet.fromJSON({
    sub: '4',
    username: 'z',
    email: 'sw',
    avatar: 'ab',
    phoneNumber: 'cd',
})

const initialData = {
    ti: 'Y3VydmUyNTUxOSBUZXN0IFRva2Vu', // "curve25519 Test Token"
    attributes: attributes.encode(),
}

test('generators are correct', () => {
    // const numGenerators = 51
    // const generators: MontgomeryPointWrapper[] = []
    // for (let i = 0; i < numGenerators; ++i) {
    //     generators.push(Curve25519.computeGeneratorForIndex(i))
    // }
    // const b64s = generators.map((wp: MontgomeryPointWrapper) => wp.montPoint.toBase64())
    // const preGenGenerators = Curve25519.getPreGenGenerators(50)
    // console.log(`num pregen generators`, preGenGenerators.length)
    // for (let i = 0; i < numGenerators; ++i) {
    //     expect(generators[i].equals(preGenGenerators[i + 1]))
    // }
})

test(`testing public key is correct`, () => {
    const pkc = getPrivateKeyContainer()
    const curve = Curve25519
    const gen = curve.getGenerator()
    const priv = curve.Zq.createElementFromBytes(pkc.getPrivateKeyBytes())
    const pub = curve.Gq.getIdentityElement()
    curve.Gq.modexp(gen, priv, pub)

    const pub64 = pub.montPoint.toBase64()
    console.log({ pub64 })
    expect(pub64).toBe(params.g[0])
})

const oidcparams = [
    { name: 'sub', type: 'string', hash: 0 },
    { name: 'name', type: 'string', hash: 0 },
    { name: 'given_name', type: 'string', hash: 0 },
    { name: 'family_name', type: 'string', hash: 0 },
    { name: 'middle_name', type: 'string', hash: 0 },
    { name: 'preferred_username', type: 'string', hash: 0 },
    { name: 'profile', type: 'string', hash: 0 },
    { name: 'picture', type: 'string', hash: 0 },
    { name: 'website', type: 'string', hash: 0 },
    { name: 'email', type: 'string', hash: 0 },
    { name: 'email_verified', type: 'boolean', hash: 0 },
    { name: 'gender', type: 'string', hash: 0 },
    { name: 'birthdate', type: 'string', hash: 0 },
    { name: 'zoneinfo', type: 'string', hash: 0 },
    { name: 'locale', type: 'string', hash: 0 },
    { name: 'phone_number', type: 'string', hash: 0 },
    { name: 'phone_number_verified', type: 'boolean', hash: 0 },
    { name: 'address', type: 'object', hash: 1 },
    { name: 'updated_at', type: 'number', hash: 0 },
]

const params = {
    uidp: 'VVByb3ZlVFMgY3VydmUyNTUxOSBUZXN0IHYxLjA=', // "UProveTS curve25519 Test v1.0"
    descGq: { name: 'curve25519' },
    e: uint8ArrayToBase64(oidcparams.map((p: any) => p.hash)),
    g: [
        'Pi3jvvshW6JQsNj3K6SNcHTa2KufY0eMcAGQyYEu+/Q4vEHi+rZmN03dgeDzVKyfjONzM7DvO+BJM+GQXUJJzg==',
        'AJ9ce9SOVHhIzneef/ndWPrFobQgNALyIPy9Uxj9OUAmB7ECb2/YVi/XIAcDoLCTx/WlQWPLJ8TNhMyvHBzwtA==',
        'cJQw0nL707wK0zP53eOtDLGUQMC0VC6gPMEjip8e4Fk5hiXV8CwGEYhaUwjjSco3VwSZiNJkglxkDF9Q+OQZbg==',
        'JjJz2ukKfYUyWrhScSa+5SwMRN0hDkfk6RyaCmKHQDEzl30J2I0RTWSxXF6GiKsjXxnUdxzIjo6aIL+O24cnxg==',
        'LnGZl4j8pWV5LZItC+D551oulv2FXpFOWZs6NPg4klchZm55JwQX4uSlkaZK95gI6mgYR2UpBe21gQ6EC0md2A==',
        'I5+DNyPrGwTxddmJuoh4p5Tgr8XsNaxV0GpP5HvkUfg4K8TNsHjmh9UVjvdlmVIZpLE+gjx2SC+5XyuP3S7/xA==',
        'NRFWVDNHKnkFGte1neU3u5AMY9v2uyaUrLlgSRcsei84ALWY3Ijc47upbjl3+upo25irzJ69AdfCrYc+nvFOww==',
        // 'Lu+X3070RiBXejVPKHyuM/KQ1ydfxLUbCwPdzt4VwaAtJ0dfJmB48iZUo/C2jVtES5QauWy0XW/XnPtCN01y0Q==',
        // 'be/rb+HIgaSJ2nB9yji9opmTeUBcoaP6aUygN3fLkzwLwYWemBMskgf1or/BxtXZ0sIsfUE2wx/j3nK4WFXCnw==',
        // 'YQNwxinocnan2/7Iw67XvEFQ0mYtZmeYZMOvaZ//OnUJKXVLoze3qVwzCfKiYgCeblkucN2fMUk+NJ8cj2UnvA==',
        // 'HCyGG12XmRw4MapSU5yF3Qz2221yBH1hPgiPqyY+wLwNEIoRXnsoPuJCyJuOV/kTHAtencM9gpKZhtJd/SWwkg==',
        // 'Rr5KbApwpVoIU4KndIxRIAHUrT1uy9QSYixWDp/yCzoj2J4Qg7VP3WHRiAYiISKn4GkRi/Vy+QyiRPDSM6QPiQ==',
        // 'HOHAU8t+te+3LRbnWG7n6msLf2+aiA6oP1qqCk7stXkSjGZaGCypC71JJtkFKtsuiGB9CsTq9/MV+QY8gw9Grw==',
        // 'ExCYU6Cs+Jcpzpo896UYI0f4uz92WA0y0/1gI1Fdj2USjCFol3279w+iIa4mY5j06OwGvbxBDDVz3zhYbdvPLQ==',
        // 'HeBZCUZESLFvpgEziqcMHWoQcHVtkRp0kfWNSdMF5oM2ikcf75/6eTFHL+3tIYAthTH4TpMEt9LyWCEu/oMSOQ==',
        // 'AxF7yHsRInrjwQSLcT6IgxC5+tWG0UXxZU+4jWhrYpYii5mHTYSS/51g6eT+quzbRN7VNrzKN1qqkukXDu7bCQ==',
        // 'U5D0ln3IlN9ln6bHbjjiGARwIrYOGBmOqgctIf/g6Ug4xf0aWMGYoLvAhnxAkuX4h8mMnp5Nfv2U+ckU2lG3OQ==',
        // 'fk2lcamrCN/Rll6uSj/1JtgYleCXny3dVEhDe2QUCyw1LyvHW0eVvPv3lg6h3UlbR+HrCm37TCm/9RYquCgh+Q==',
        // 'Cy03UVT5ASex4UyI6zHlfM9PactM4HzCbJigICj9wws/RyU6nUfASyeRhRKNPKLse4l5TgVD4aR3b/Gmszfo2Q==',
        // 'bwxkYmXzOY5WcYc3xAAZkjRmfJfGMjVsCZzLFLYYmTkApipD1U3ny54IvJCvZcli4mZ+Ic1cr3RXjDO7gmqD3w==',
        // 'D/ihEvkDM1AsqNQpC80DD5IbySxRXBdMxunXToBTeSQ989HaC0a0xwVdIRmyJ4S5+iZHmm07VviaW+Zk1hdS8A==',
        // 'XAKaidYagp7ax51O+yTnFs54Ui7zzvUlcIx4K2+gFc4QPp3xI7epMKF3oanxHfpLLJJie4/ey51Kn3UxfOmO9w==',
    ],
    s: uint8ArrayToBase64(msrcryptoUtilities.stringToBytes(JSON.stringify(oidcparams))),
}

const serializedParams = {
    uidp: 'VVByb3ZlVFMgY3VydmUyNTUxOSBUZXN0IHYxLjA=',
    descGq: { name: 'curve25519' },
    e: 'AAEBAAA=', // 'AAAAAAAAAAAAAAAAAAAAAAABAA==',
    g: [
        'Pi3jvvshW6JQsNj3K6SNcHTa2KufY0eMcAGQyYEu+/Q4vEHi+rZmN03dgeDzVKyfjONzM7DvO+BJM+GQXUJJzg==',
        'AJ9ce9SOVHhIzneef/ndWPrFobQgNALyIPy9Uxj9OUAmB7ECb2/YVi/XIAcDoLCTx/WlQWPLJ8TNhMyvHBzwtA==',
        'cJQw0nL707wK0zP53eOtDLGUQMC0VC6gPMEjip8e4Fk5hiXV8CwGEYhaUwjjSco3VwSZiNJkglxkDF9Q+OQZbg==',
        'JjJz2ukKfYUyWrhScSa+5SwMRN0hDkfk6RyaCmKHQDEzl30J2I0RTWSxXF6GiKsjXxnUdxzIjo6aIL+O24cnxg==',
        'LnGZl4j8pWV5LZItC+D551oulv2FXpFOWZs6NPg4klchZm55JwQX4uSlkaZK95gI6mgYR2UpBe21gQ6EC0md2A==',
        'I5+DNyPrGwTxddmJuoh4p5Tgr8XsNaxV0GpP5HvkUfg4K8TNsHjmh9UVjvdlmVIZpLE+gjx2SC+5XyuP3S7/xA==',
        'NRFWVDNHKnkFGte1neU3u5AMY9v2uyaUrLlgSRcsei84ALWY3Ijc47upbjl3+upo25irzJ69AdfCrYc+nvFOww==',
        // 'Lu+X3070RiBXejVPKHyuM/KQ1ydfxLUbCwPdzt4VwaAtJ0dfJmB48iZUo/C2jVtES5QauWy0XW/XnPtCN01y0Q==',
        // 'be/rb+HIgaSJ2nB9yji9opmTeUBcoaP6aUygN3fLkzwLwYWemBMskgf1or/BxtXZ0sIsfUE2wx/j3nK4WFXCnw==',
        // 'YQNwxinocnan2/7Iw67XvEFQ0mYtZmeYZMOvaZ//OnUJKXVLoze3qVwzCfKiYgCeblkucN2fMUk+NJ8cj2UnvA==',
        // 'HCyGG12XmRw4MapSU5yF3Qz2221yBH1hPgiPqyY+wLwNEIoRXnsoPuJCyJuOV/kTHAtencM9gpKZhtJd/SWwkg==',
        // 'Rr5KbApwpVoIU4KndIxRIAHUrT1uy9QSYixWDp/yCzoj2J4Qg7VP3WHRiAYiISKn4GkRi/Vy+QyiRPDSM6QPiQ==',
        // 'HOHAU8t+te+3LRbnWG7n6msLf2+aiA6oP1qqCk7stXkSjGZaGCypC71JJtkFKtsuiGB9CsTq9/MV+QY8gw9Grw==',
        // 'ExCYU6Cs+Jcpzpo896UYI0f4uz92WA0y0/1gI1Fdj2USjCFol3279w+iIa4mY5j06OwGvbxBDDVz3zhYbdvPLQ==',
        // 'HeBZCUZESLFvpgEziqcMHWoQcHVtkRp0kfWNSdMF5oM2ikcf75/6eTFHL+3tIYAthTH4TpMEt9LyWCEu/oMSOQ==',
        // 'AxF7yHsRInrjwQSLcT6IgxC5+tWG0UXxZU+4jWhrYpYii5mHTYSS/51g6eT+quzbRN7VNrzKN1qqkukXDu7bCQ==',
        // 'U5D0ln3IlN9ln6bHbjjiGARwIrYOGBmOqgctIf/g6Ug4xf0aWMGYoLvAhnxAkuX4h8mMnp5Nfv2U+ckU2lG3OQ==',
        // 'fk2lcamrCN/Rll6uSj/1JtgYleCXny3dVEhDe2QUCyw1LyvHW0eVvPv3lg6h3UlbR+HrCm37TCm/9RYquCgh+Q==',
        // 'Cy03UVT5ASex4UyI6zHlfM9PactM4HzCbJigICj9wws/RyU6nUfASyeRhRKNPKLse4l5TgVD4aR3b/Gmszfo2Q==',
        // 'bwxkYmXzOY5WcYc3xAAZkjRmfJfGMjVsCZzLFLYYmTkApipD1U3ny54IvJCvZcli4mZ+Ic1cr3RXjDO7gmqD3w==',
        // 'D/ihEvkDM1AsqNQpC80DD5IbySxRXBdMxunXToBTeSQ989HaC0a0xwVdIRmyJ4S5+iZHmm07VviaW+Zk1hdS8A==',
        // 'XAKaidYagp7ax51O+yTnFs54Ui7zzvUlcIx4K2+gFc4QPp3xI7epMKF3oanxHfpLLJJie4/ey51Kn3UxfOmO9w==',
    ],
    s:
        'W3sibmFtZSI6InN1YiIsInR5cGUiOiJzdHJpbmciLCJoYXNoIjowfSx7Im5hbWUiOiJuYW1lIiwidHlwZSI6InN0cmluZyIsImhhc2giOjB9LHsibmFtZSI6ImdpdmVuX25hbWUiLCJ0eXBlIjoic3RyaW5nIiwiaGFzaCI6MH0seyJuYW1lIjoiZmFtaWx5X25hbWUiLCJ0eXBlIjoic3RyaW5nIiwiaGFzaCI6MH0seyJuYW1lIjoibWlkZGxlX25hbWUiLCJ0eXBlIjoic3RyaW5nIiwiaGFzaCI6MH0seyJuYW1lIjoicHJlZmVycmVkX3VzZXJuYW1lIiwidHlwZSI6InN0cmluZyIsImhhc2giOjB9LHsibmFtZSI6InByb2ZpbGUiLCJ0eXBlIjoic3RyaW5nIiwiaGFzaCI6MH0seyJuYW1lIjoicGljdHVyZSIsInR5cGUiOiJzdHJpbmciLCJoYXNoIjowfSx7Im5hbWUiOiJ3ZWJzaXRlIiwidHlwZSI6InN0cmluZyIsImhhc2giOjB9LHsibmFtZSI6ImVtYWlsIiwidHlwZSI6InN0cmluZyIsImhhc2giOjB9LHsibmFtZSI6ImVtYWlsX3ZlcmlmaWVkIiwidHlwZSI6ImJvb2xlYW4iLCJoYXNoIjowfSx7Im5hbWUiOiJnZW5kZXIiLCJ0eXBlIjoic3RyaW5nIiwiaGFzaCI6MH0seyJuYW1lIjoiYmlydGhkYXRlIiwidHlwZSI6InN0cmluZyIsImhhc2giOjB9LHsibmFtZSI6InpvbmVpbmZvIiwidHlwZSI6InN0cmluZyIsImhhc2giOjB9LHsibmFtZSI6ImxvY2FsZSIsInR5cGUiOiJzdHJpbmciLCJoYXNoIjowfSx7Im5hbWUiOiJwaG9uZV9udW1iZXIiLCJ0eXBlIjoic3RyaW5nIiwiaGFzaCI6MH0seyJuYW1lIjoicGhvbmVfbnVtYmVyX3ZlcmlmaWVkIiwidHlwZSI6ImJvb2xlYW4iLCJoYXNoIjowfSx7Im5hbWUiOiJhZGRyZXNzIiwidHlwZSI6Im9iamVjdCIsImhhc2giOjF9LHsibmFtZSI6InVwZGF0ZWRfYXQiLCJ0eXBlIjoibnVtYmVyIiwiaGFzaCI6MH1d',
}

function getPrivateKeyContainer(): PrivateKeyContainer {
    // NOTE: This secret is NOT secret.  It is provided for test purposes and alternate
    // validation
    const y0str = 'V4DkqgjMwYVxA1uVqLHLBsdUJlj+0ToEL9xCLxv0sX4='
    return new InMemoryPrivateKeyContainer(base64ToUint8Array(y0str))
}

test(`curve25519 proof`, () => {
    const issuerParams = IssuerParams.ParseIssuerParams(serializedParams)
    console.log({ issuerParams, serializedParams })
    expect(issuerParams).toBeDefined()

    // TO DO, confirm we're getting the righ Zq modulus
    const rng = new ZqRNG(Curve25519.Gq.Zq)
    const prover = new Prover(rng, issuerParams)
    const issuerSession = new IssuerSession(
        getPrivateKeyContainer(),
        1,
        rng,
        issuerParams,
        initialData.attributes,
        base64ToUint8Array(initialData.ti)
    )
    // Prover information - do we want more here?
    const pi = Uint8Array.from([1])

    // Issuer creates the first message
    const firstMsg = issuerSession.getFirstMessage()
    expect(firstMsg).toBeDefined()
    expect(firstMsg.sa.length).toEqual(1)
    expect(firstMsg.sb.length).toEqual(1)

    expect(firstMsg.sa[0]).toBeDefined()
    expect(firstMsg.sb[0]).toBeDefined()

    // Prover parses it and creates the second message
    const proverFirstMsg = prover.ip.ParseFirstMessage(firstMsg)
    const secondMsg = prover.generateSecondMessage(
        1,
        initialData.attributes,
        base64ToUint8Array(initialData.ti),
        pi,
        null,
        proverFirstMsg,
        false
    )
    expect(secondMsg).toBeDefined()
    expect(secondMsg.sc.length).toEqual(1)

    // Issuer creates third message
    issuerSession.receiveSecondMessage(secondMsg)
    const thirdMessage = issuerSession.getThirdMessage()

    expect(thirdMessage).toBeDefined()

    // Prover generates tokens
    const proverThirdMessage = prover.ip.ParseThirdMessage(thirdMessage)
    const keyAndBaseToken = prover.generateTokens(proverThirdMessage)
    // console.log({ keyAndToken: keyAndBaseToken })
    expect(keyAndBaseToken).toBeDefined()
    expect(keyAndBaseToken[0]).toBeDefined()
    expect(keyAndBaseToken[0].key).toBeDefined()
    expect(keyAndBaseToken[0].token).toBeDefined()
    // Prover generates proof

    const token: SerializedUProveToken = {
        ...keyAndBaseToken[0].token,
        uidp: uint8ArrayToBase64(issuerParams.uidp),
        ti: initialData.ti,
        pi: uint8ArrayToBase64(pi),
    }
    const { key } = keyAndBaseToken[0]

    const disclosed = [2, 4]
    const committed = null

    const message = base64ToUint8Array('dW5pdCB0ZXN0IHRva2VuIG1lc3NhZ2U=')
    const messageD = base64ToUint8Array('dW5pdCB0ZXN0IGRldmljZSBtZXNzYWdl')
    const scopeData: ScopeData = { p: 1, s: Uint8Array.from([90, 11, 117, 103, 103, 108, 97]) }
    const commitmentPrivateValues = {}
    const t1 = performanceTimer.now()
    const ukat = issuerParams.ParseKeyAndToken({ key, token })

    const proof = prover.generateProof(
        ukat,
        disclosed,
        committed || [],
        message,
        messageD,
        initialData.attributes,
        scopeData,
        commitmentPrivateValues
    )
    const time = performanceTimer.now() - t1
    console.log(`generate proof time: ${time}`)
    console.log({ proof })

    expect(proof).toBeDefined()

    const verifier = new Verifier(issuerParams)
    expect(verifier.verifyTokenSignature(ukat.token)).toBe(true)

    const parsedProof = verifier.parseProof(proof)

    const isValid = verifier.verify(parsedProof, ukat.token, disclosed, [], message, scopeData, messageD)
    // console.log(isValid)
    // console.log(protocolTest.ip.serialize())
    // console.log(uint8ArrayToBase64(protocolTest.y0.toByteArrayUnsigned()))
    // console.log(protocolTest.issuerSession.serialize())
    expect(isValid).toBe(true)

    // test that prover can compute the pseudonym correctly
    const pseudo = prover.computePseudonym(scopeData, initialData.attributes)
    expect(pseudo).toBe(proof.Ps)
})

test(`curve25519 issuance serialization`, () => {
    const issuerParams = IssuerParams.ParseIssuerParams(serializedParams)
    console.log({ issuerParams, serializedParams })
    expect(issuerParams).toBeDefined()

    // TO DO, confirm we're getting the righ Zq modulus
    const rng = new ZqRNG(Curve25519.Gq.Zq)
    const prover = new Prover(rng, issuerParams)
    const issuerSession = new IssuerSession(
        getPrivateKeyContainer(),
        1,
        rng,
        issuerParams,
        initialData.attributes,
        base64ToUint8Array(initialData.ti)
    )
    // Prover information - do we want more here?
    const pi = Uint8Array.from([1])

    // Issuer creates the first message
    const firstMsg = issuerSession.getFirstMessage()
    expect(firstMsg).toBeDefined()
    expect(firstMsg.sa.length).toEqual(1)
    expect(firstMsg.sb.length).toEqual(1)

    expect(firstMsg.sa[0]).toBeDefined()
    expect(firstMsg.sb[0]).toBeDefined()

    // Prover parses it and creates the second message
    const proverFirstMsg = prover.ip.ParseFirstMessage(firstMsg)
    // test that the parsedMessage equals the original
    expect(proverFirstMsg.sa[0].equals(issuerSession.firstMessage!.sa[0])).toBeTruthy()
    expect(proverFirstMsg.sb[0].equals(issuerSession.firstMessage!.sb[0])).toBeTruthy()
    expect(proverFirstMsg.sz.equals(issuerSession.firstMessage!.sz)).toBeTruthy()

    const secondMsg = prover.generateSecondMessage(
        1,
        initialData.attributes,
        base64ToUint8Array(initialData.ti),
        pi,
        null,
        proverFirstMsg,
        false
    )
    expect(secondMsg).toBeDefined()
    expect(secondMsg.sc.length).toEqual(1)

    // Issuer creates third message
    issuerSession.receiveSecondMessage(secondMsg)

    // expect the messages to match between prover and issuer
    const Zq = issuerParams.descGq.getZq()
    const shouldBeSC = Zq.createElementFromInteger(0)
    Zq.add(prover.sigmaCPrime![0], prover.beta1!, shouldBeSC)

    expect(issuerSession.secondMessage!.sc[0].equals(shouldBeSC)).toBeTruthy()

    const thirdMessage = issuerSession.getThirdMessage()

    expect(thirdMessage).toBeDefined()

    // Prover generates tokens
    const proverThirdMessage = prover.ip.ParseThirdMessage(thirdMessage)

    expect(proverThirdMessage.sr[0].equals(issuerSession.thirdMessage!.sr[0]))

    const keyAndBaseToken = prover.generateTokens(proverThirdMessage)
    // console.log({ keyAndToken: keyAndBaseToken })
    expect(keyAndBaseToken).toBeDefined()
    expect(keyAndBaseToken[0]).toBeDefined()
    expect(keyAndBaseToken[0].key).toBeDefined()
    expect(keyAndBaseToken[0].token).toBeDefined()
    // Prover generates proof

    const token: SerializedUProveToken = {
        ...keyAndBaseToken[0].token,
        uidp: uint8ArrayToBase64(issuerParams.uidp),
        ti: initialData.ti,
        pi: uint8ArrayToBase64(pi),
    }
    const { key } = keyAndBaseToken[0]
})
