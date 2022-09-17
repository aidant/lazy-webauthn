import {
  errorExpectedAttestationResponse,
  errorInvalidChallenge,
  errorInvalidCredentialExists,
  errorInvalidCredentialLength,
  errorInvalidOrigin,
  errorInvalidRelyingPartyId,
  errorInvalidType,
  errorUnsupportedAlgorithm,
  errorUnsupportedAttestationFormat,
  errorUserNotPresent,
  errorUserNotVerified,
  ServerCreateCredentialOptions,
} from '@lazy/webauthn-common'
import { decode as decodeCBOR } from 'cbor-x/decode.js'
import {
  AttestationStatementFormatIdentifier,
  AttestationStatementFormatIdentifiers,
} from './attestation-statement-format-identifiers.js'
import { ServerCreateCredentialBackend } from './backend.js'
// @ts-expect-error no types
import COSE from 'cose-to-jwk'
import { isAuthenticatorAttestationResponse, PublicKeyCredential } from './public-key-credential.js'

/*
  The WebAuthn specification goes through the process for registering a new
  credential. This function is responsible for steps 3-26 outlined here:
  https://www.w3.org/TR/webauthn/#sctn-registering-a-new-credential
*/
export const createCredential = async (
  options: ServerCreateCredentialOptions,
  backend: ServerCreateCredentialBackend,
  credential: PublicKeyCredential
) => {
  /*
    Step: 3

    Let response be credential.response. If response is not an instance of
    AuthenticatorAttestationResponse, abort the ceremony with a user-visible
    error.
  */
  const response = credential.response
  if (!isAuthenticatorAttestationResponse(response)) {
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

    Let JSONtext be the result of running UTF-8 decode on the value of
    response.clientDataJSON.

    Note: Using any implementation of UTF-8 decode is acceptable as long as it
    yields the same result as that yielded by the UTF-8 decode algorithm. In
    particular, any leading byte order mark (BOM) MUST be stripped.
  */
  const JSONtext = new TextDecoder('utf-8').decode(response.clientDataJSON)
  /*
    Step: 6

    Let C, the client data claimed as collected during the credential creation,
    be the result of running an implementation-specific JSON parser on JSONtext.

    Note: C may be any implementation-specific data structure representation,
    as long as C’s components are referenceable, as required by this algorithm.
  */
  const C = JSON.parse(JSONtext)

  /*
    Step: 7

    Verify that the value of C.type is webauthn.create.
  */
  if (C.type !== 'webauthn.create') {
    throw errorInvalidType('webauthn.create', C.type)
  }

  /*
    Step: 8

    Verify that the value of C.challenge equals the base64url encoding of
    options.challenge.
  */
  if (C.challenge !== btoa(String.fromCharCode(...new Uint8Array(options.challenge)))) {
    throw errorInvalidChallenge()
  }

  /*
    Step: 9

    Verify that the value of C.origin matches the Relying Party's origin.
  */
  if (C.origin !== options.serverOrigin) {
    throw errorInvalidOrigin(C.origin, options.serverOrigin)
  }

  /*
    Step: 10

    Let hash be the result of computing a hash over response.clientDataJSON
    using SHA-256.
  */
  const hash = await crypto.subtle.digest('SHA-256', response.clientDataJSON)

  /*
    Step: 11

    Perform CBOR decoding on the attestationObject field of the
    AuthenticatorAttestationResponse structure to obtain the attestation
    statement format fmt, the authenticator data authData, and the attestation
    statement attStmt.
  */
  const { fmt, authData, attStmt } = decodeCBOR(response.attestationObject) as {
    fmt: string
    authData: Uint8Array
    attStmt: unknown
  }

  /*
    Step: 12

    Verify that the rpIdHash in authData is the SHA-256 hash of the RP ID
    expected by the Relying Party.
  */
  const acrualRpIdHash = authData.slice(0, 32)
  const expectedRpIdHash = await crypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode(options.serverId)
  )
  if (authData !== expectedRpIdHash) {
    throw errorInvalidRelyingPartyId(acrualRpIdHash, expectedRpIdHash)
  }

  const flagUP = authData[33] & (1 << 0)
  const flagUV = authData[33] & (1 << 2)
  const flagBE = authData[33] & (1 << 3)
  const flagBS = authData[33] & (1 << 4)
  const flagAT = authData[33] & (1 << 6)
  const flagED = authData[33] & (1 << 7)

  /*
    Step: 13

    Verify that the UP bit of the flags in authData is set.
  */
  if (!flagUP) {
    throw errorUserNotPresent()
  }

  /*
    Step: 14

    If the Relying Party requires user verification for this registration,
    verify that the UV bit of the flags in authData is set.
  */
  if (options.userVerification && !flagUV) {
    throw errorUserNotVerified()
  }

  /*
    Step: 15

    If the Relying Party uses the credential’s backup eligibility to inform its
    user experience flows and/or policies, evaluate the BE bit of the flags in
    authData.

    Step: 16

    If the Relying Party uses the credential’s backup state to inform its user
    experience flows and/or policies, evaluate the BS bit of the flags in
    authData, and then store the value for evaluation in future authentication
    ceremonies.
  */
  const backupEligibility = Boolean(flagBE)
  const backupState = Boolean(flagBS)
  await backend.handleBackupFlags?.({ backupEligibility, backupState })

  /*
    Step: 17

    Verify that the "alg" parameter in the credential public key in authData
    matches the alg attribute of one of the items in options.pubKeyCredParams.
  */
  const credentialIdLength = (authData[53] << 8) | authData[54]
  const credentialId = authData.slice(55, 55 + credentialIdLength)
  const publicKeyBytes = authData.slice(55 + credentialIdLength)
  const credentialPublicKey = COSE(publicKeyBytes.buffer)

  if (!options.algorithms.includes(credentialPublicKey.alg)) {
    throw errorUnsupportedAlgorithm(options.algorithms, credentialPublicKey.alg)
  }

  /*
    Step: 18

    Verify that the values of the client extension outputs in
    clientExtensionResults and the authenticator extension outputs in the
    extensions in authData are as expected, considering the client extension
    input values that were given in options.extensions and any specific policy
    of the Relying Party regarding unsolicited extensions, i.e., those that were
    not specified as part of options.extensions. In the general case, the
    meaning of "are as expected" is specific to the Relying Party and which
    extensions are in use.

    Note: Client platforms MAY enact local policy that sets additional
    authenticator extensions or client extensions and thus cause values to
    appear in the authenticator extension outputs or client extension outputs
    that were not originally specified as part of options.extensions. Relying
    Parties MUST be prepared to handle such situations, whether it be to ignore
    the unsolicited extensions or reject the attestation. The Relying Party can
    make this decision based on local policy and the extensions in use.

    Note: Since all extensions are OPTIONAL for both the client and the
    authenticator, the Relying Party MUST also be prepared to handle cases where
    none or not all of the requested extensions were acted upon.
  */

  /*
    Step: 19

    Determine the attestation statement format by performing a USASCII
    case-sensitive match on fmt against the set of supported WebAuthn
    Attestation Statement Format Identifier values. An up-to-date list of
    registered WebAuthn Attestation Statement Format Identifier values is
    maintained in the IANA "WebAuthn Attestation Statement Format Identifiers"
    registry [IANA-WebAuthn-Registries] established by [RFC8809].
  */
  if (
    !AttestationStatementFormatIdentifiers.includes(fmt as AttestationStatementFormatIdentifier)
  ) {
    throw errorUnsupportedAttestationFormat(AttestationStatementFormatIdentifiers, fmt)
  }

  /*
    Step: 20

    Verify that attStmt is a correct attestation statement, conveying a valid
    attestation signature, by using the attestation statement format fmt’s
    verification procedure given attStmt, authData and hash.

    Note: Each attestation statement format specifies its own verification
    procedure. See § 8 Defined Attestation Statement Formats for the
    initially-defined formats, and [IANA-WebAuthn-Registries] for the up-to-date
    list.
  */

  /*
    Step: 21

    If validation is successful, obtain a list of acceptable trust anchors (i.e.
    attestation root certificates) for that attestation type and attestation
    statement format fmt, from a trusted source or from policy. For example,
    the FIDO Metadata Service [FIDOMetadataService] provides one way to obtain
    such information, using the aaguid in the attestedCredentialData in
    authData.
  */

  /*
    Step: 22

    Assess the attestation trustworthiness using the outputs of the verification
    procedure in step 19, as follows:

      - If no attestation was provided, verify that None attestation is
        acceptable under Relying Party policy.

      - If self attestation was used, verify that self attestation is acceptable
        under Relying Party policy.

      - Otherwise, use the X.509 certificates returned as the attestation trust
        path from the verification procedure to verify that the attestation
        publickey either correctly chains up to an acceptable root certificate,
        or is itself an acceptable certificate (i.e., it and the root
        certificate obtained in Step 19 may be the same).
  */

  /*
    Step: 23

    Verify that the credentialId is ≤ 1023 bytes. Credential IDs larger than
    this many bytes SHOULD cause the RP to fail this registration ceremony.
  */
  if (credentialIdLength <= 1023) {
    throw errorInvalidCredentialLength(credentialIdLength)
  }

  /*
    Step: 24

    Verify that the credentialId is not yet registered for any user. If the
    credentialId is already known then the Relying Party SHOULD fail this
    registration ceremony.

    NOTE: The rationale for Relying Parties rejecting duplicate credential IDs
    is as follows: credential IDs contain sufficient entropy that accidental
    duplication is very unlikely. However, attestation types other than self
    attestation do not include a self-signature to explicitly prove possession
    of the credential private key at registration time. Thus an attacker who has
    managed to obtain a user’s credential ID and credential public key for a
    site (this could be potentially accomplished in various ways), could attempt
    to register a victim’s credential as their own at that site. If the Relying
    Party accepts this new registration and replaces the victim’s existing
    credential registration, and the credentials are discoverable, then the
    victim could be forced to sign into the attacker’s account at their next
    attempt. Data saved to the site by the victim in that state would then be
    available to the attacker.
  */
  const credentialIdExists = await backend.hasCredential(credential.rawId)
  if (credentialIdExists) {
    throw errorInvalidCredentialExists()
  }

  /*
    Step: 25

    If the attestation statement attStmt verified successfully and is found to
    be trustworthy, then register the new credential with the user account that
    was denoted in options.user:

      - Associate the user account with the credentialId and credentialPublicKey
        in authData.attestedCredentialData, as appropriate for the Relying
        Party's system.

      - Associate the credentialId with a new stored signature counter value
        initialized to the value of authData.signCount.

    It is RECOMMENDED to also:

      - Associate the credentialId with the transport hints returned by calling
        credential.response.getTransports(). This value SHOULD NOT be modified
        before or after storing it. It is RECOMMENDED to use this value to
        populate the transports of the allowCredentials option in future get()
        calls to help the client know how to find a suitable authenticator.

    Step: 26

    If the attestation statement attStmt successfully verified but is not
    trustworthy per step 20 above, the Relying Party SHOULD fail the
    registration ceremony.

    NOTE: However, if permitted by policy, the Relying Party MAY register the
    credential ID and credential public key but treat the credential as one with
    self attestation (see § 6.5.3 Attestation Types). If doing so, the Relying
    Party is asserting there is no cryptographic proof that the public key
    credential has been generated by a particular authenticator model. See
    [FIDOSecRef] and [UAFProtocol] for a more detailed discussion.
  */
  const signatureCounter = BigInt(
    '0x' + [...authData.slice(33, 37)].map((byte) => byte.toString(16).padStart(2, '0')).join('')
  )
  const transports = response.getTransports()

  await backend.setCredential({
    userId: options.userId,
    userDisplayName: options.userDisplayName,
    backupEligibility,
    backupState,
    credentialId,
    credentialPublicKey,
    signatureCounter,
    transports,
  })
}
