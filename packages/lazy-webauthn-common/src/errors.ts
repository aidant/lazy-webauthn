export type WebAuthnErrorCode =
  | 'ERR_EXPECTED_ATTESTATION_RESPONSE'
  | 'ERR_EXPECTED_ASSERTION_RESPONSE'
  | 'ERR_INVALID_TYPE'
  | 'ERR_INVALID_CHALLENGE'
  | 'ERR_INVALID_ORIGIN'
  | 'ERR_INVALID_RELYING_PARTY_ID'
  | 'ERR_USER_NOT_PRESENT'
  | 'ERR_USER_NOT_VERIFIED'
  | 'ERR_UNSUPPORTED_ALGORITHM'
  | 'ERR_UNSUPPORTED_ATTESTATION_FORMAT'
  | 'ERR_INVALID_CREDENTIAL_LENGTH'
  | 'ERR_INVALID_CREDENTIAL_EXISTS'
  | 'ERR_INVALID_CREDENTIAL_NOT_FOUND'
  | 'ERR_INVALID_SIGNATURE'
  | 'ERR_DESERIALIZING_CREDENTIAL'

export class WebAuthnError extends Error {
  constructor(public readonly code: WebAuthnErrorCode, message: string) {
    super(message)
  }
}

export const errorExpectedAttestationResponse = (received: unknown) =>
  new WebAuthnError(
    'ERR_EXPECTED_ATTESTATION_RESPONSE',
    `Unable to verify credential, expected to receive an "AuthenticatorAttestationResponse" but received "${received}"`
  )

export const errorExpectedAssertionResponse = (received: unknown) =>
  new WebAuthnError(
    'ERR_EXPECTED_ASSERTION_RESPONSE',
    `Unable to verify credential, expected to receive an "AuthenticatorAssertionResponse" but received "${received}"`
  )

export const errorInvalidType = (expected: 'webauthn.create' | 'webauthn.get', received: unknown) =>
  new WebAuthnError(
    'ERR_INVALID_TYPE',
    `Unable to verify credential, invalid type expected: "${expected}", but received: "${received}"`
  )

export const errorInvalidChallenge = () =>
  new WebAuthnError('ERR_INVALID_CHALLENGE', 'Unable to verify credential, invalid challenge')

export const errorInvalidOrigin = (expected: unknown, received: unknown) =>
  new WebAuthnError(
    'ERR_INVALID_CHALLENGE',
    `Unable to verify credential, invalid origin expected: "${expected}" but received: "${received}"`
  )

export const errorInvalidRelyingPartyId = (expected: unknown, received: unknown) =>
  new WebAuthnError(
    'ERR_INVALID_RELYING_PARTY_ID',
    `Unable to verify credential, invalid relying party id expected: "${expected}" but received: "${received}"`
  )

export const errorUserNotPresent = () =>
  new WebAuthnError('ERR_USER_NOT_PRESENT', 'Unable to verify credential, the user is not present')

export const errorUserNotVerified = () =>
  new WebAuthnError(
    'ERR_USER_NOT_VERIFIED',
    'Unable to verify credential, the user is not verified'
  )

export const errorUnsupportedAlgorithm = (algorithms: readonly string[], algorithm: string) =>
  new WebAuthnError(
    'ERR_UNSUPPORTED_ALGORITHM',
    algorithms.length === 1
      ? `Unable to verify credential, unsupported algorithm, expected: "${algorithms[0]}" but received: "${algorithm}"`
      : `Unable to verify credential, unsupported algorithm, expected one of: "${algorithms.join(
          '", "'
        )}" but received: "${algorithm}"`
  )

export const errorUnsupportedAttestationFormat = (identifiers: readonly string[], format: string) =>
  new WebAuthnError(
    'ERR_UNSUPPORTED_ATTESTATION_FORMAT',
    identifiers.length === 1
      ? `Unable to verify credential, unsupported attestation format, expected: "${identifiers[0]}" but received: "${format}"`
      : `Unable to verify credential, unsupported attestation statement format, expected one of "${identifiers.join(
          '", "'
        )}" but got "${format}"`
  )

export const errorInvalidCredentialLength = (received: number) =>
  new WebAuthnError(
    'ERR_INVALID_CREDENTIAL_LENGTH',
    `Unable to verify credential, credential id is too long, expected less than 1024 bytes but got ${received} bytes`
  )

export const errorInvalidCredentialExists = () =>
  new WebAuthnError(
    'ERR_INVALID_CREDENTIAL_EXISTS',
    'Unable to verify credential, credential already exists'
  )

export const errorInvalidCredentialNotFound = () =>
  new WebAuthnError(
    'ERR_INVALID_CREDENTIAL_NOT_FOUND',
    'Unable to verify credential, credential not found'
  )

export const errorInvalidSignature = () =>
  new WebAuthnError(
    'ERR_INVALID_SIGNATURE',
    'Unable to get credential, the signature is not valid for the credential public key'
  )

export const errorDeserializingCredential = (
  property: string,
  expected: string,
  received: string
) =>
  new WebAuthnError(
    'ERR_DESERIALIZING_CREDENTIAL',
    `Unable to deserialize ${property}, expected type of "${expected}" but received "${received}"`
  )
