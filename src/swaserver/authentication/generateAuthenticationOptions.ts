import { b64urlencode } from '../../shared.ts';
import type {
  AuthenticationExtensionsClientInputs,
  PublicKeyCredentialDescriptorFuture,
  PublicKeyCredentialRequestOptionsJSON,
} from '../../swatypes/index.ts';

export type GenerateAuthenticationOptionsOpts = {
  allowCredentials?: PublicKeyCredentialDescriptorFuture[];
  challenge: string;
  timeout?: number;
  extensions?: AuthenticationExtensionsClientInputs;
  rpID?: string;
};

/**
 * Prepare a value to pass into navigator.credentials.get(...) for authenticator "login"
 *
 * @param allowCredentials Authenticators previously registered by the user, if any. If undefined
 * the client will ask the user which credential they want to use
 * @param challenge Random value the authenticator needs to sign and pass back
 * user for authentication
 * @param timeout How long (in ms) the user can take to complete authentication
 * @param userVerification Set to `'discouraged'` when asserting as part of a 2FA flow, otherwise
 * set to `'preferred'` or `'required'` as desired.
 * @param extensions Additional plugins the authenticator or browser should use during authentication
 * @param rpID Valid domain name (after `https://`)
 */
export async function generateAuthenticationOptions(
  options: GenerateAuthenticationOptionsOpts,
): Promise<PublicKeyCredentialRequestOptionsJSON> {
  const {
    allowCredentials,
    challenge,
    timeout = 60000,
    extensions,
    rpID,
  } = options;

  return {
    challenge,
    allowCredentials: allowCredentials?.map((cred) => ({
      ...cred,
      id: b64urlencode(Buffer.from(cred.id as Uint8Array).toString("base64")),
    })),
    timeout,
    userVerification: "discouraged",
    extensions,
    rpId: rpID,
  };
}
