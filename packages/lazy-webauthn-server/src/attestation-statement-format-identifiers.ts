export const AttestationStatementFormatIdentifiers = [
  'packed',
  'tpm',
  'android-key',
  'android-safetynet',
  'fido-u2f',
  'apple',
  'none',
] as const

export type AttestationStatementFormatIdentifier =
  typeof AttestationStatementFormatIdentifiers[number]
