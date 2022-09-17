export interface AuthenticatorResponse {
  clientDataJSON: ArrayBuffer
}

export type AuthenticatorTransport = 'ble' | 'internal' | 'nfc' | 'usb'

export interface AuthenticatorAttestationResponse extends AuthenticatorResponse {
  attestationObject: ArrayBuffer
  getTransports(): AuthenticatorTransport[]
  getAuthenticatorData(): ArrayBuffer
  getPublicKey(): ArrayBuffer | null
  getPublicKeyAlgorithm(): number
}

export interface AuthenticatorAssertionResponse extends AuthenticatorResponse {
  authenticatorData: ArrayBuffer
  signature: ArrayBuffer
  userHandle: ArrayBuffer | null
}

export interface CredentialPropertiesOutput {
  rk?: boolean
}

export type UvmEntry = number[]

export type UvmEntries = UvmEntry[]

export interface AuthenticationExtensionsClientOutputs {
  appid?: boolean
  credProps?: CredentialPropertiesOutput
  uvm?: UvmEntries
}

export interface PublicKeyCredential {
  id: string
  rawId: ArrayBuffer
  type: 'public-key'
  response: AuthenticatorAttestationResponse | AuthenticatorAssertionResponse
  getClientExtensionResults: () => AuthenticationExtensionsClientOutputs
}

export const isAuthenticatorAttestationResponse = (
  response: AuthenticatorAttestationResponse | AuthenticatorAssertionResponse
): response is AuthenticatorAttestationResponse =>
  'attestationObject' in response &&
  response.attestationObject instanceof ArrayBuffer &&
  'getTransports' in response &&
  typeof response.getTransports === 'function' &&
  'getAuthenticatorData' in response &&
  typeof response.getAuthenticatorData === 'function' &&
  'getPublicKey' in response &&
  typeof response.getPublicKey === 'function' &&
  'getPublicKeyAlgorithm' in response &&
  typeof response.getPublicKeyAlgorithm === 'function'

export const isAuthenticatorAssertionResponse = (
  response: AuthenticatorAttestationResponse | AuthenticatorAssertionResponse
): response is AuthenticatorAssertionResponse =>
  'authenticatorData' in response &&
  response.authenticatorData instanceof ArrayBuffer &&
  'signature' in response &&
  response.signature instanceof ArrayBuffer
