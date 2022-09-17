/*
  The WebAuthn specification goes through the process for registering a new
  credential. This function and the associated deserialize credential
  counterpart are responsible for transmission of data during step 3 outlined
  here: https://www.w3.org/TR/webauthn/#sctn-registering-a-new-credential
*/
export const serializeCredential = (credential: PublicKeyCredential): FormData => {
  const data = new FormData()

  data.set('id', credential.id)
  data.set('rawId', new Blob([credential.rawId], { type: 'application/octet-stream' }))
  data.set('type', credential.type)
  data.set(
    'response.clientDataJSON',
    new Blob([credential.response.clientDataJSON], {
      type: 'application/octet-stream',
    })
  )

  if (credential.response instanceof AuthenticatorAttestationResponse) {
    data.set(
      'response.attestationObject',
      new Blob([credential.response.attestationObject], {
        type: 'application/cbor',
      })
    )

    data.set(
      'response.getTransports()',
      JSON.stringify(
        (credential.response as unknown as { getTransports: () => string[] }).getTransports()
      )
    )

    const publicKey = (
      credential.response as unknown as { getPublicKey: () => ArrayBuffer | null }
    ).getPublicKey()
    if (publicKey) {
      data.set(
        'response.getPublicKey()',
        new Blob([publicKey], {
          type: 'application/octet-stream',
        })
      )
    }

    data.set(
      'response.getPublicKeyAlgorithm()',
      JSON.stringify(
        (
          credential.response as unknown as { getPublicKeyAlgorithm: () => number }
        ).getPublicKeyAlgorithm()
      )
    )
  } else if (credential.response instanceof AuthenticatorAssertionResponse) {
    data.set(
      'response.authenticatorData',
      new Blob([credential.response.authenticatorData], {
        type: 'application/octet-stream',
      })
    )
    data.set(
      'response.signature',
      new Blob([credential.response.signature], {
        type: 'application/octet-stream',
      })
    )
    if (credential.response.userHandle) {
      data.set(
        'response.userHandle',
        new Blob([credential.response.userHandle], {
          type: 'application/octet-stream',
        })
      )
    }
  }

  data.set('getClientExtensionResults()', JSON.stringify(credential.getClientExtensionResults()))

  return data
}
