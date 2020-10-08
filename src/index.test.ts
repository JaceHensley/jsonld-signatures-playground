import {Secp256k1Key, Secp256k1Signature} from '@affinidi/tiny-lds-ecdsa-secp256k1-2019'

const jsigs = require('jsonld-signatures')
const jsonld = require('jsonld')

const { AssertionProofPurpose } = jsigs.purposes

const did = 'did:elem:EiBOH3jRdJZmRE4ew_lKc0RgSDsZphs3ddXmz2MHfKHXcQ'
const didLongForm = `${did};elem:initial-state=eyJwcm90ZWN0ZWQiOiJleUp2Y0dWeVlYUnBiMjRpT2lKamNtVmhkR1VpTENKcmFXUWlPaUlqY0hKcGJXRnllU0lzSW1Gc1p5STZJa1ZUTWpVMlN5SjkiLCJwYXlsb2FkIjoiZXlKQVkyOXVkR1Y0ZENJNkltaDBkSEJ6T2k4dmR6TnBaQzV2Y21jdmMyVmpkWEpwZEhrdmRqSWlMQ0p3ZFdKc2FXTkxaWGtpT2x0N0ltbGtJam9pSTNCeWFXMWhjbmtpTENKMWMyRm5aU0k2SW5OcFoyNXBibWNpTENKMGVYQmxJam9pVTJWamNESTFObXN4Vm1WeWFXWnBZMkYwYVc5dVMyVjVNakF4T0NJc0luQjFZbXhwWTB0bGVVaGxlQ0k2SWpBeVl6QTBaR00yTUdRME1UWmtaRFl3TkdJNVlUQTJaV0l3WkRObE5USTNOVEpsT1RNM1pXSXpabVUwTmpRMlpUQXdOV1ZqTnpjd1l6YzJObUl4TWpBNU5pSjlMSHNpYVdRaU9pSWpjbVZqYjNabGNua2lMQ0oxYzJGblpTSTZJbkpsWTI5MlpYSjVJaXdpZEhsd1pTSTZJbE5sWTNBeU5UWnJNVlpsY21sbWFXTmhkR2x2Ymt0bGVUSXdNVGdpTENKd2RXSnNhV05MWlhsSVpYZ2lPaUl3TXpKaU5ETmpZV0ZtTkRBellXTmxOV0ZtTWpBd1ptSmlPRGxsWm1Oa1pEYzJNVEF4TWpSak5UUXpZVFEwT1dNMU1USTBNelUzTWprd1lURmtOalU0TVRZaWZWMHNJbUYxZEdobGJuUnBZMkYwYVc5dUlqcGJJaU53Y21sdFlYSjVJbDBzSW1GemMyVnlkR2x2YmsxbGRHaHZaQ0k2V3lJamNISnBiV0Z5ZVNKZGZRIiwic2lnbmF0dXJlIjoiRWVlaGxnajdjVnA0N0dHRXBUNEZieFV1WG1VY1dXZktHQkI2aUxnQTgtd3BLcXViSHVEeVJYQzQ4SldMMjZQRzVZV0xtZFRwcV8wVHNkVmhVMlEwYUEifQ`
const didDoc = {
  '@context': 'https://w3id.org/security/v2',
  publicKey: [
    {
      id: 'did:elem:EiBOH3jRdJZmRE4ew_lKc0RgSDsZphs3ddXmz2MHfKHXcQ#primary',
      usage: 'signing',
      type: 'Secp256k1VerificationKey2018',
      publicKeyHex: '02c04dc60d416dd604b9a06eb0d3e52752e937eb3fe4646e005ec770c766b12096',
    },
    {
      id: 'did:elem:EiBOH3jRdJZmRE4ew_lKc0RgSDsZphs3ddXmz2MHfKHXcQ#recovery',
      usage: 'recovery',
      type: 'Secp256k1VerificationKey2018',
      publicKeyHex: '032b43caaf403ace5af200fbb89efcdd7610124c543a449c5124357290a1d65816',
    },
  ],
  authentication: ['did:elem:EiBOH3jRdJZmRE4ew_lKc0RgSDsZphs3ddXmz2MHfKHXcQ#primary'],
  assertionMethod: ['did:elem:EiBOH3jRdJZmRE4ew_lKc0RgSDsZphs3ddXmz2MHfKHXcQ#primary'],
  id: 'did:elem:EiBOH3jRdJZmRE4ew_lKc0RgSDsZphs3ddXmz2MHfKHXcQ',
}

const keys = {
  primaryKey: {
    publicKey: '02c04dc60d416dd604b9a06eb0d3e52752e937eb3fe4646e005ec770c766b12096',
    privateKey: 'dbcec07b9f9816ac5cec1dadadde64fc0ed610be39b06a77a238e95df36d774a',
  },
  recoveryKey: {
    publicKey: '032b43caaf403ace5af200fbb89efcdd7610124c543a449c5124357290a1d65816',
    privateKey: '03f8547441c20a6be216d8335e9dd96021a0a5de84db12bbe40af1bb7cbdc276',
  },
}

const credential = {
  '@context': [
    'https://www.w3.org/2018/credentials/v1',
    {
      '@version': 1.1,
      data: {
        '@id': 'https://example.com/data',
        '@type': '@json',
      }
    }
  ],
  id: 'urn:uuid:75442486-0878-440c-9db1-a7006c25a39f',
  type: ['VerifiableCredential'],
  holder: {id: did},
  credentialSubject: {
    data: {
      '@type': 'Thing',
      key: 'value'
    }
  },
  issuanceDate: new Date().toISOString(),
  issuer: didLongForm
}

const documentLoader = async (url: string): Promise<any> => {
  if (url.startsWith('did:')) {
    return {
      contextUrl: null,
      document: didDoc,
      documentUrl: url,
    }
  }

  return jsonld.documentLoaders.node()(url)
}

describe('jsonld-signatures', () => {
  it('signs and verifies a credential', async () => {
    expect.assertions(1)

    const signed = await jsigs.sign({...credential}, {
      suite: new Secp256k1Signature({
        key: new Secp256k1Key({
          id: `${did}#primary`,
          controller: didLongForm,
          privateKeyHex: keys.primaryKey.privateKey,
        }),
      }),
      documentLoader,
      purpose: new AssertionProofPurpose({controller: didDoc}),
      compactProof: false,
    })

    const result = await jsigs.verify(signed, {
      suite: new Secp256k1Signature({
        key: new Secp256k1Key({
          id: signed.proof.verificationMethod,
          controller: signed.issuer,
          publicKeyHex: keys.primaryKey.publicKey,
        }),
      }),
      documentLoader,
      purpose: new AssertionProofPurpose({controller: didDoc}),
      compactProof: false,
    })

    expect(result.verified).toBeTruthy()
  })

  it('throws when there is an unmapped type string', async () => {
    expect.assertions(1)

    // Should throw due to an unmapped type value
    await expect(
      jsigs.sign({...credential, type: [...credential.type, 'OtherType']}, {
        suite: new Secp256k1Signature({
          key: new Secp256k1Key({
            id: `${did}#primary`,
            controller: didLongForm,
            privateKeyHex: keys.primaryKey.privateKey,
          }),
        }),
        documentLoader,
        purpose: new AssertionProofPurpose({controller: didDoc}),
        compactProof: false,
      })
    ).rejects.toThrow()
  })

  describe('does not verify a credential that has been modified', () => {
    it('(adding unmapped type)', async () => {
      expect.assertions(1)

      const signed = await jsigs.sign({...credential}, {
        suite: new Secp256k1Signature({
          key: new Secp256k1Key({
            id: `${did}#primary`,
            controller: didLongForm,
            privateKeyHex: keys.primaryKey.privateKey,
          }),
        }),
        documentLoader,
        purpose: new AssertionProofPurpose({controller: didDoc}),
        compactProof: false,
      })

      const result = await jsigs.verify({...signed, type: [...signed.type, 'OtherType']}, {
        suite: new Secp256k1Signature({
          key: new Secp256k1Key({
            id: signed.proof.verificationMethod,
            controller: signed.issuer,
            publicKeyHex: keys.primaryKey.publicKey,
          }),
        }),
        documentLoader,
        purpose: new AssertionProofPurpose({controller: didDoc}),
        compactProof: false,
      })

      // Should be false because the credential has been tampered with
      expect(result.verified).toBeFalsy()
    })

    it('(removing unmapped type)', async () => {
      expect.assertions(1)

      const signed = await jsigs.sign({...credential, type: [...credential.type, 'Unmapped']}, {
        suite: new Secp256k1Signature({
          key: new Secp256k1Key({
            id: `${did}#primary`,
            controller: didLongForm,
            privateKeyHex: keys.primaryKey.privateKey,
          }),
        }),
        documentLoader,
        purpose: new AssertionProofPurpose({controller: didDoc}),
        compactProof: false,
      })

      const result = await jsigs.verify({...signed, type: [...credential.type]}, {
        suite: new Secp256k1Signature({
          key: new Secp256k1Key({
            id: signed.proof.verificationMethod,
            controller: signed.issuer,
            publicKeyHex: keys.primaryKey.publicKey,
          }),
        }),
        documentLoader,
        purpose: new AssertionProofPurpose({controller: didDoc}),
        compactProof: false,
      })

      // Should be false because the credential has been tampered with
      expect(result.verified).toBeFalsy()
    })

    it('(issuanceDate)', async () => {
      expect.assertions(1)

      const signed = await jsigs.sign({...credential}, {
        suite: new Secp256k1Signature({
          key: new Secp256k1Key({
            id: `${did}#primary`,
            controller: didLongForm,
            privateKeyHex: keys.primaryKey.privateKey,
          }),
        }),
        documentLoader,
        purpose: new AssertionProofPurpose({controller: didDoc}),
        compactProof: false,
      })

      const result = await jsigs.verify({...signed, issuanceDate: new Date(0).toISOString()}, {
        suite: new Secp256k1Signature({
          key: new Secp256k1Key({
            id: signed.proof.verificationMethod,
            controller: signed.issuer,
            publicKeyHex: keys.primaryKey.publicKey,
          }),
        }),
        documentLoader,
        purpose: new AssertionProofPurpose({controller: didDoc}),
        compactProof: false,
      })

      expect(result.verified).toBeFalsy()
    })
  })
})
