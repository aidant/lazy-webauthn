export interface StoredCredential {
  userId: string
  userDisplayName: string
  backupEligibility: boolean
  backupState: boolean
  credentialId: ArrayBuffer
  credentialPublicKey: { alg: string }
  signatureCounter: bigint
  transports: string[]
}

export interface CredentialBackend {
  hasCredential: (credentialId: ArrayBuffer) => Promise<boolean> | boolean
  getCredential: (
    credentialId: ArrayBuffer
  ) => Promise<StoredCredential | null> | StoredCredential | null
  setCredential: (options: StoredCredential) => Promise<void> | void
  setSignatureCounter: (credentialId: ArrayBuffer, signatureCounter: bigint) => Promise<void> | void
  handleSignatureCounterError?: (
    credentialId: ArrayBuffer,
    signatureCounter: bigint
  ) => Promise<void> | void
  handleBackupFlags?: (options: {
    backupEligibility: boolean
    backupState: boolean
  }) => Promise<void> | void
}

export interface ServerGetCredentialBackend
  extends Pick<
    CredentialBackend,
    'handleBackupFlags' | 'getCredential' | 'setSignatureCounter' | 'handleSignatureCounterError'
  > {}

export interface ServerCreateCredentialBackend
  extends Pick<CredentialBackend, 'handleBackupFlags' | 'hasCredential' | 'setCredential'> {}
