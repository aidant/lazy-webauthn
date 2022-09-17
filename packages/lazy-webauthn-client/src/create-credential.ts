import {
  Algorithms,
  ClientCreateCredentialOptions,
  errorExpectedAttestationResponse,
} from '@lazy/webauthn-common'

/*
  The WebAuthn specification goes through the process for registering a new
  credential. This function is responsible for steps 1-3 outlined here:
  https://www.w3.org/TR/webauthn/#sctn-registering-a-new-credential
*/
export const createCredential = async (
  options: ClientCreateCredentialOptions
): Promise<PublicKeyCredential> => {
  /*
    Step: 1

    Let options be a new PublicKeyCredentialCreationOptions structure configured
    to the Relying Party's needs for the ceremony.
  */
  const publicKey: PublicKeyCredentialCreationOptions = {
    rp: {
      id: options.serverId,
      name: options.serverName,
    },
    user: {
      id: new TextEncoder().encode(options.userId),
      name: options.userDisplayName,
      displayName: options.userDisplayName,
    },
    challenge: options.challenge,
    pubKeyCredParams: options.algorithms.map((algorithm) => ({
      type: 'public-key',
      alg: Algorithms[algorithm],
    })),
  }

  /*
    Step: 2

    Call navigator.credentials.create() and pass options as the publicKey
    option. Let credential be the result of the successfully resolved promise.
    If the promise is rejected, abort the ceremony with a user-visible error,
    or otherwise guide the user experience as might be determinable from the
    context available in the rejected promise. For example if the promise is
    rejected with an error code equivalent to "InvalidStateError", the user
    might be instructed to use a different authenticator. For information on
    different error contexts and the circumstances leading to them, see § 6.3.2
    The authenticatorMakeCredential Operation.
  */
  const credential = await navigator.credentials.create({ publicKey })

  /*
    Step: 3

    Let response be credential.response. If response is not an instance of
    AuthenticatorAttestationResponse, abort the ceremony with a user-visible
    error.
  */
  if (
    !((credential as PublicKeyCredential)?.response instanceof AuthenticatorAttestationResponse)
  ) {
    throw errorExpectedAttestationResponse(
      (credential as PublicKeyCredential)?.response?.constructor.name
    )
  }

  return credential as PublicKeyCredential & { response: AuthenticatorAttestationResponse }
}
