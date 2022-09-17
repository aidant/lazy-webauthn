import {
  errorExpectedAttestationResponse,
  errorInvalidChallenge,
  errorInvalidCredentialNotFound,
  errorInvalidOrigin,
  errorInvalidRelyingPartyId,
  errorInvalidSignature,
  errorInvalidType,
  errorUserNotPresent,
  errorUserNotVerified,
  ServerGetCredentialOptions,
} from '@lazy/webauthn-common'
import { ServerGetCredentialBackend } from './backend.js'
import { isAuthenticatorAssertionResponse, PublicKeyCredential } from './public-key-credential.js'

/*
  The WebAuthn specification goes through the process for verifying an
  authentication assertion. This function is responsible for steps 3-23 outlined
  here: https://www.w3.org/TR/webauthn/#sctn-verifying-assertion
*/
export const getCredential = async (
  options: ServerGetCredentialOptions,
  backend: ServerGetCredentialBackend,
  credential: PublicKeyCredential
) => {
  /*
    Step: 3

    Let response be credential.response. If response is not an instance of
    AuthenticatorAssertionResponse, abort the ceremony with a user-visible
    error.
  */
  const response = credential.response

  if (!isAuthenticatorAssertionResponse(response)) {
    throw errorExpectedAttestationResponse('unknown')
  }

  /*
    Step: 4

    Let clientExtensionResults be the result of calling
    credential.getClientExtensionResults().
  */
  const clientExtensionResults = credential.getClientExtensionResults()

  /*
    Step: 5

    If options.allowCredentials is not empty, verify that credential.id
    identifies one of the public key credentials listed in
    options.allowCredentials.
  */
  const foundCredential = options.credentials?.find(
    ({ credentialId }) => credentialId === credential.id
  )
  if (options.credentials?.length && !foundCredential) {
    throw errorInvalidCredentialNotFound()
  }

  /*
    Step: 6

    Identify the user being authenticated and verify that this user is the owner
    of the public key credential source credentialSource identified by
    credential.id:

      - If the user was identified before the authentication ceremony was
        initiated, e.g., via a username or cookie, verify that the identified
        user is the owner of credentialSource. If response.userHandle is
        present, let userHandle be its value. Verify that userHandle also maps
        to the same user.

      - If the user was not identified before the authentication ceremony was
        initiated, verify that response.userHandle is present, and that the user
        identified by this value is the owner of credentialSource.
  */

  /*
    Step: 7

    Using credential.id (or credential.rawId, if base64url encoding is
    inappropriate for your use case), look up the corresponding credential
    public key and let credentialPublicKey be that credential public key.s
  */
  const storedCredential = await backend.getCredential(credential.rawId)
  if (!storedCredential) {
    throw errorInvalidCredentialNotFound()
  }
  const credentialPublicKey = storedCredential.credentialPublicKey

  /*
    Step: 8

    Let cData, authData and sig denote the value of response’s clientDataJSON,
    authenticatorData, and signature respectively.
  */
  const cData = response.clientDataJSON
  const authData = new Uint8Array(response.authenticatorData)
  const sig = response.signature

  /*
    Step: 9

    Let JSONtext be the result of running UTF-8 decode on the value of cData.

    Note: Using any implementation of UTF-8 decode is acceptable as long as it
    yields the same result as that yielded by the UTF-8 decode algorithm. In
    particular, any leading byte order mark (BOM) MUST be stripped.
  */
  const JSONtext = new TextDecoder('utf-8').decode(cData)

  /*
    Step: 10

    Let C, the client data claimed as used for the signature, be the result of
    running an implementation-specific JSON parser on JSONtext.

    Note: C may be any implementation-specific data structure representation,
    as long as C’s components are referenceable, as required by this algorithm.
  */
  const C = JSON.parse(JSONtext)

  /*
    Step: 11

    Verify that the value of C.type is the string webauthn.get.
  */
  if (C.type !== 'webauthn.get') {
    throw errorInvalidType('webauthn.get', C.type)
  }

  /*
    Step: 12

    Verify that the value of C.challenge equals the base64url encoding of
    options.challenge.
  */
  if (C.challenge !== btoa(String.fromCharCode(...new Uint8Array(options.challenge)))) {
    throw errorInvalidChallenge()
  }

  /*
    Step: 13

    Verify that the value of C.origin matches the Relying Party's origin.
  */
  if (C.origin !== options.serverOrigin) {
    throw errorInvalidOrigin(options.serverOrigin, C.origin)
  }

  /*
    Step: 14

    Verify that the rpIdHash in authData is the SHA-256 hash of the RP ID
    expected by the Relying Party.

    Note: If using the appid extension, this step needs some special logic. See
    § 10.1.1 FIDO AppID Extension (appid) for details.
  */
  const acrualRpIdHash = authData.slice(0, 32)
  const expectedRpIdHash = await crypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode(options.serverId)
  )
  if (authData !== expectedRpIdHash) {
    throw errorInvalidRelyingPartyId(expectedRpIdHash, acrualRpIdHash)
  }

  const flagUP = authData[33] & (1 << 0)
  const flagUV = authData[33] & (1 << 2)
  const flagBE = authData[33] & (1 << 3)
  const flagBS = authData[33] & (1 << 4)
  const flagAT = authData[33] & (1 << 6)
  const flagED = authData[33] & (1 << 7)

  /*
    Step: 15

    Verify that the UP bit of the flags in authData is set.
  */
  if (!flagUP) {
    throw errorUserNotPresent()
  }

  /*
    Step: 16

    If the Relying Party requires user verification for this assertion, verify
    that the UV bit of the flags in authData is set.
  */
  if (options.userVerification && !flagUV) {
    throw errorUserNotVerified()
  }

  /*
    Step: 17

    If the credential backup state is used as part of Relying Party business
    logic or policy, compare the previously stored value with the BS bit of the
    flags in authData, perform evaluation, and then store the new value.
  */
  const backupEligibility = Boolean(flagBE)
  const backupState = Boolean(flagBS)
  await backend.handleBackupFlags?.({ backupEligibility, backupState })

  /*
    Step: 18

    Verify that the values of the client extension outputs in
    clientExtensionResults and the authenticator extension outputs in the
    extensions in authData are as expected, considering the client extension
    input values that were given in options.extensions and any specific policy of
    the Relying Party regarding unsolicited extensions, i.e., those that were not
    specified as part of options.extensions. In the general case, the meaning of
    "are as expected" is specific to the Relying Party and which extensions are in
    use.

    Note: Client platforms MAY enact local policy that sets additional
    authenticator extensions or client extensions and thus cause values to appear
    in the authenticator extension outputs or client extension outputs that were
    not originally specified as part of options.extensions. Relying Parties MUST
    be prepared to handle such situations, whether it be to ignore the unsolicited
    extensions or reject the assertion. The Relying Party can make this decision
    based on local policy and the extensions in use.

    Note: Since all extensions are OPTIONAL for both the client and the
    authenticator, the Relying Party MUST also be prepared to handle cases where
    none or not all of the requested extensions were acted upon.
  */

  /*
    Step: 19

    Let hash be the result of computing a hash over the cData using SHA-256.
  */
  const hash = await crypto.subtle.digest('SHA-256', response.clientDataJSON)

  /*
    Step: 20

    Using credentialPublicKey, verify that sig is a valid signature over the
    binary concatenation of authData and hash.

    Note: This verification step is compatible with signatures generated by FIDO
    U2F authenticators. See § 6.1.2 FIDO U2F Signature Format Compatibility.
  */
  const signatureIsValid = await crypto.subtle.verify(
    credentialPublicKey.alg,
    await crypto.subtle.importKey('jwk', credentialPublicKey, credentialPublicKey.alg, true, [
      'verify',
    ]),
    sig,
    new Uint8Array([...authData, ...new Uint8Array(hash)])
  )
  if (!signatureIsValid) {
    throw errorInvalidSignature()
  }

  /*
    Step: 21

    Let storedSignCount be the stored signature counter value associated with
    credential.id. If authData.signCount is nonzero or storedSignCount is nonzero,
    then run the following sub-step:

      - If authData.signCount is

        - greater than storedSignCount:
          Update storedSignCount to be the value of authData.signCount.

        - less than or equal to storedSignCount:
          This is a signal that the authenticator may be cloned, i.e. at least
          two copies of the credential private key may exist and are being used in
          parallel. Relying Parties should incorporate this information into their
          risk scoring. Whether the Relying Party updates storedSignCount in this
          case, or not, or fails the authentication ceremony or not, is Relying
          Party-specific.
  */
  const signatureCounter = BigInt(
    '0x' + [...authData.slice(33, 37)].map((byte) => byte.toString(16).padStart(2, '0')).join('')
  )
  if (signatureCounter > storedCredential.signatureCounter) {
    await backend.setSignatureCounter(credential.rawId, signatureCounter)
  } else {
    await backend.handleSignatureCounterError?.(credential.rawId, signatureCounter)
  }

  /*
    Step: 22

    If all the above steps are successful, continue with the authentication
    ceremony as appropriate. Otherwise, fail the authentication ceremony.
  */
  return {
    userId: storedCredential.userId,
    userDisplayName: storedCredential.userDisplayName,
    backupEligibility,
    backupState,
    credentialId: credential.rawId,
    credentialPublicKey,
    signatureCounter,
    transports: storedCredential.transports,
  }
}
