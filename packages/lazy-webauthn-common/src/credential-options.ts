import { Algorithm } from './algorithms.js'

export interface CredentialOptions {
  serverId: string
  serverName: string
  serverOrigin: string

  userId: string
  userDisplayName: string

  challenge: ArrayBuffer

  algorithms: Algorithm[]
  credentials?: { credentialId: string; transports: string[] }[]

  timeout?: number
  userVerification: boolean
}

export interface ClientCreateCredentialOptions
  extends Pick<
    CredentialOptions,
    'serverId' | 'serverName' | 'userId' | 'userDisplayName' | 'challenge' | 'algorithms'
  > {}

export interface ServerCreateCredentialOptions
  extends Pick<
    CredentialOptions,
    | 'serverId'
    | 'serverOrigin'
    | 'userId'
    | 'userDisplayName'
    | 'challenge'
    | 'algorithms'
    | 'userVerification'
  > {}

export interface ClientGetCredentialOptions
  extends Pick<
    CredentialOptions,
    'serverId' | 'credentials' | 'challenge' | 'timeout' | 'userVerification'
  > {}

export interface ServerGetCredentialOptions
  extends Pick<
    CredentialOptions,
    'serverId' | 'serverOrigin' | 'credentials' | 'challenge' | 'userVerification'
  > {}
