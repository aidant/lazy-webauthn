import { errorDeserializingCredential } from '@lazy/webauthn-common'
import {
  AuthenticatorAssertionResponse,
  AuthenticatorAttestationResponse,
  PublicKeyCredential,
} from './public-key-credential.js'

/*
  The WebAuthn specification goes through the process for registering a new
  credential. This function and the associated serialize credential counterpart
  are responsible for transmission of data during step 3 outlined here:
  https://www.w3.org/TR/webauthn/#sctn-registering-a-new-credential
*/
export const deserializeCredential = async (data: FormData): Promise<PublicKeyCredential> => {
  const result: Partial<PublicKeyCredential> = {}

  const errors: Error[] = []

  const dataId = data.get('id')
  const dataRawId = data.get('rawId')
  const dataType = data.get('type')
  const dataResponseClientDataJSON = data.get('response.clientDataJSON')

  // AuthenticatorAttestationResponse
  const dataResponseAttestationObject = data.get('response.attestationObject')
  const dataResponseGetTransports = data.get('response.getTransports()')
  const dataGetPublicKey = data.get('response.getPublicKey()')
  const dataGetPublicKeyAlgorithm = data.get('response.getPublicKeyAlgorithm()')

  // AuthenticatorAssertionResponse
  const dataResponseAuthenticatorData = data.get('response.authenticatorData')
  const dataResponseSignature = data.get('response.signature')
  const dataResponseUserHandle = data.get('response.userHandle')

  const dataGetClientExtensionResults = data.get('getClientExtensionResults()')

  if (typeof dataId === 'string') {
    result.id = dataId
  } else {
    errors.push(
      errorDeserializingCredential(
        'credential.id',
        'string',
        dataId?.constructor?.name || typeof dataId
      )
    )
  }

  if (dataRawId instanceof Blob) {
    result.rawId = await dataRawId.arrayBuffer()
  } else {
    errors.push(
      errorDeserializingCredential(
        'credential.rawId',
        'Blob',
        dataRawId?.constructor?.name || typeof dataRawId
      )
    )
  }

  if (typeof dataType === 'string') {
    result.type = dataType as PublicKeyCredential['type']
  } else {
    errors.push(
      errorDeserializingCredential(
        'credential.id',
        'string',
        dataType?.constructor?.name || typeof dataType
      )
    )
  }

  if (dataResponseClientDataJSON instanceof Blob) {
    result.response = {} as PublicKeyCredential['response']
    result.response.clientDataJSON = await dataResponseClientDataJSON.arrayBuffer()
  } else {
    errors.push(
      errorDeserializingCredential(
        'credential.response.clientDataJSON',
        'Blob',
        dataResponseClientDataJSON?.constructor?.name || typeof dataResponseClientDataJSON
      )
    )
  }

  if (dataResponseAttestationObject) {
    if (dataResponseAttestationObject instanceof Blob) {
      ;(result.response as AuthenticatorAttestationResponse).attestationObject =
        await dataResponseAttestationObject.arrayBuffer()
    } else {
      errors.push(
        errorDeserializingCredential(
          'credential.response.attestationObject',
          'Blob',
          dataResponseAttestationObject?.constructor?.name || typeof dataResponseAttestationObject
        )
      )
    }

    if (typeof dataResponseGetTransports === 'string') {
      try {
        const transports = JSON.parse(dataResponseGetTransports)
        ;(result.response as AuthenticatorAttestationResponse).getTransports = () => transports
      } catch {
        errors.push(
          errorDeserializingCredential(
            'credential.response.getTransports()',
            'json',
            dataResponseGetTransports
          )
        )
      }
    } else {
      errors.push(
        errorDeserializingCredential(
          'credential.response.getTransports()',
          'string',
          dataResponseGetTransports?.constructor?.name || typeof dataResponseGetTransports
        )
      )
    }

    if (dataGetPublicKey instanceof Blob) {
      const publicKey = await dataGetPublicKey.arrayBuffer()
      ;(result.response as AuthenticatorAttestationResponse).getPublicKey = () => publicKey
    } else if (!dataGetPublicKey) {
      ;(result.response as AuthenticatorAttestationResponse).getPublicKey = () => null
    } else {
      errors.push(
        errorDeserializingCredential(
          'credential.response.getPublicKey()',
          'Blob',
          dataGetPublicKey?.constructor?.name || typeof dataGetPublicKey
        )
      )
    }

    if (typeof dataGetPublicKeyAlgorithm === 'string') {
      try {
        const publicKeyAlgorithm = JSON.parse(dataGetPublicKeyAlgorithm)
        ;(result.response as AuthenticatorAttestationResponse).getPublicKeyAlgorithm = () =>
          publicKeyAlgorithm
      } catch {
        errors.push(
          errorDeserializingCredential(
            'credential.response.getPublicKeyAlgorithm()',
            'json',
            dataGetPublicKeyAlgorithm
          )
        )
      }
    } else {
      errors.push(
        errorDeserializingCredential(
          'credential.response.getPublicKeyAlgorithm()',
          'string',
          dataGetPublicKeyAlgorithm?.constructor?.name || typeof dataGetPublicKeyAlgorithm
        )
      )
    }
  } else if (dataResponseAuthenticatorData) {
    if (dataResponseAuthenticatorData instanceof Blob) {
      ;(result.response as AuthenticatorAssertionResponse).authenticatorData =
        await dataResponseAuthenticatorData.arrayBuffer()
    } else {
      errors.push(
        errorDeserializingCredential(
          'credential.response.authenticatorData',
          'Blob',
          dataResponseAuthenticatorData?.constructor?.name || typeof dataResponseAuthenticatorData
        )
      )
    }

    if (dataResponseSignature instanceof Blob) {
      ;(result.response as AuthenticatorAssertionResponse).signature =
        await dataResponseSignature.arrayBuffer()
    } else {
      errors.push(
        errorDeserializingCredential(
          'credential.response.signature',
          'Blob',
          dataResponseSignature?.constructor?.name || typeof dataResponseSignature
        )
      )
    }

    if (dataResponseUserHandle instanceof Blob) {
      ;(result.response as AuthenticatorAssertionResponse).userHandle =
        await dataResponseUserHandle.arrayBuffer()
    } else if (!dataResponseUserHandle) {
      ;(result.response as AuthenticatorAssertionResponse).userHandle = null
    } else {
      errors.push(
        errorDeserializingCredential(
          'credential.response.userHandle',
          'Blob',
          dataResponseUserHandle?.constructor?.name || typeof dataResponseUserHandle
        )
      )
    }
  } else {
    errors.push(
      errorDeserializingCredential(
        'credential.response',
        'AuthenticatorAttestationResponse or AuthenticatorAssertionResponse',
        'unknown'
      )
    )
  }

  if (typeof dataGetClientExtensionResults === 'string') {
    try {
      const clientExtensionResults = JSON.parse(dataGetClientExtensionResults)
      result.getClientExtensionResults = () => clientExtensionResults
    } catch {
      errors.push(
        errorDeserializingCredential(
          'credential.getClientExtensionResults()',
          'json',
          dataGetClientExtensionResults
        )
      )
    }
  } else {
    errors.push(
      errorDeserializingCredential(
        'credential.getClientExtensionResults()',
        'string',
        dataGetClientExtensionResults?.constructor?.name || typeof dataGetClientExtensionResults
      )
    )
  }

  if (errors.length === 1) {
    throw errors[0]
  } else if (errors.length) {
    throw new AggregateError(errors, 'Unable to deserialize credential')
  }

  return result as PublicKeyCredential
}
