import {
  AuthenticationCredential,
  AuthenticationResponseJSON,
  PublicKeyCredentialRequestOptionsJSON,
} from '../../swatypes';

import { bufferToBase64URLString } from '../helpers/bufferToBase64URLString';
import { base64URLStringToBuffer } from '../helpers/base64URLStringToBuffer';
import { bufferToUTF8String } from '../helpers/bufferToUTF8String';
import { toPublicKeyCredentialDescriptor } from '../helpers/toPublicKeyCredentialDescriptor';
import { identifyAuthenticationError } from '../helpers/identifyAuthenticationError';
import { WebAuthnAbortService } from '../helpers/webAuthnAbortService';
import { toAuthenticatorAttachment } from '../helpers/toAuthenticatorAttachment';

/**
 * Begin authenticator "login" via WebAuthn assertion
 *
 * @param requestOptionsJSON Output from **@simplewebauthn/server**'s `generateAuthenticationOptions()`
 * @param useBrowserAutofill Initialize conditional UI to enable logging in via browser
 * autofill prompts
 */
export async function startAuthentication(
  requestOptionsJSON: PublicKeyCredentialRequestOptionsJSON,
): Promise<AuthenticationResponseJSON> {
  // We need to avoid passing empty array to avoid blocking retrieval
  // of public key
  let allowCredentials;
  if (requestOptionsJSON.allowCredentials?.length !== 0) {
    allowCredentials = requestOptionsJSON.allowCredentials?.map(
      toPublicKeyCredentialDescriptor,
    );
  }

  // We need to convert some values to Uint8Arrays before passing the credentials to the navigator
  const publicKey: PublicKeyCredentialRequestOptions = {
    ...requestOptionsJSON,
    challenge: base64URLStringToBuffer(requestOptionsJSON.challenge),
    allowCredentials,
  };

  // Prepare options for `.get()`
  const options: CredentialRequestOptions = {};

  // Finalize options
  options.publicKey = publicKey;
  // Set up the ability to cancel this request if the user attempts another
  options.signal = WebAuthnAbortService.createNewAbortSignal();

  // Wait for the user to complete assertion
  let credential;
  try {
    credential = (await navigator.credentials.get(options)) as AuthenticationCredential;
  } catch (err) {
    throw identifyAuthenticationError({ error: err as Error, options });
  }

  if (!credential) {
    throw new Error('Authentication was not completed');
  }

  const { id, rawId, response, type } = credential;

  let userHandle = undefined;
  if (response.userHandle) {
    userHandle = bufferToUTF8String(response.userHandle);
  }

  // Convert values to base64 to make it easier to send back to the server
  return {
    id,
    rawId: bufferToBase64URLString(rawId),
    response: {
      authenticatorData: bufferToBase64URLString(response.authenticatorData),
      clientDataJSON: bufferToBase64URLString(response.clientDataJSON),
      signature: bufferToBase64URLString(response.signature),
      userHandle,
    },
    type,
    clientExtensionResults: credential.getClientExtensionResults(),
    authenticatorAttachment: toAuthenticatorAttachment(
      credential.authenticatorAttachment,
    ),
  };
}
