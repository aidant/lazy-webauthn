import { ClientGetCredentialOptions, errorExpectedAssertionResponse } from '@lazy/webauthn-common'

/*
  The WebAuthn specification goes through the process for verifying an
  authentication assertion. This function is responsible for steps 1-3 outlined
  here:
  https://www.w3.org/TR/webauthn/#sctn-verifying-assertion
*/
export const getCredential = async (
  options: ClientGetCredentialOptions
): Promise<PublicKeyCredential> => {
  /*
    Step: 1

    Let options be a new PublicKeyCredentialRequestOptions structure configured
    to the Relying Party's needs for the ceremony.

    If options.allowCredentials is present, the transports member of each item
    SHOULD be set to the value returned by credential.response.getTransports()
    when the corresponding credential was registered.
  */
  const publicKey: PublicKeyCredentialRequestOptions = {
    allowCredentials: options.credentials?.map((credential) => ({
      id: Uint8Array.from(atob(credential.credentialId), (c) => c.charCodeAt(0)),
      transports: credential.transports as AuthenticatorTransport[],
      type: 'public-key',
    })),
    challenge: options.challenge,
    rpId: options.serverId,
    timeout: options.timeout,
    userVerification:
      options.userVerification === true
        ? 'required'
        : options.userVerification === false
        ? 'discouraged'
        : 'preferred',
  }

  /*
    Step: 2

    Call navigator.credentials.get() and pass options as the publicKey option
    Let credential be the result of the successfully resolved promise. If the
    promise is rejected, abort the ceremony with a user-visible error, or
    otherwise guide the user experience as might be determinable from the
    context available in the rejected promise. For information on different
    error contexts and the circumstances leading to them, see § 6.3.3 The
    authenticatorGetAssertion Operation.
  */
  const credential = await navigator.credentials.get({ publicKey })

  /*
    Step: 3

    Let response be credential.response. If response is not an instance of
    AuthenticatorAssertionResponse, abort the ceremony with a user-visible
    error.
  */
  if (!((credential as PublicKeyCredential)?.response instanceof AuthenticatorAssertionResponse)) {
    throw errorExpectedAssertionResponse(
      (credential as PublicKeyCredential)?.response?.constructor.name
    )
  }

  return credential as PublicKeyCredential & { response: AuthenticatorAssertionResponse }
}
