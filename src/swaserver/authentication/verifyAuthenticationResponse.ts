import crypto from 'crypto';

import type {
  AuthenticationResponseJSON,
  AuthenticatorDevice,
} from '../../swatypes/index.ts';
import { decodeClientDataJSON } from '../helpers/decodeClientDataJSON.ts';
import { decodeCredentialPublicKey } from '../helpers/decodeCredentialPublicKey.ts';
import { matchExpectedRPID } from '../helpers/matchExpectedRPID.ts';
import { verifyEC2 } from '../helpers/verifyEC2.ts';
import { unwrapEC2Signature } from '../helpers/unwrapEC2Signature.ts';
import { b64urldecode } from '../../shared.ts';

export type VerifyAuthenticationResponseOpts = {
  response: AuthenticationResponseJSON;
  expectedChallenge: string;
  expectedOrigin: string | string[];
  expectedRPID: string | string[];
  expectedType?: string | string[];
  authenticator: AuthenticatorDevice;
};

/**
 * Make sense of the authData buffer contained in an Attestation
 */
function parseAuthenticatorData(
  authData: Buffer,
) {
  if (authData.byteLength < 37) {
    throw new Error(
      `Authenticator data was ${authData.byteLength} bytes, expected at least 37 bytes`,
    );
  }

  const rpIdHash = authData.subarray(0, 32);
  const flagsInt = authData.readUint8(32);

  // Bit positions can be referenced here:
  // https://www.w3.org/TR/webauthn-2/#flags
  const flags = {
    up: !!(flagsInt & (1 << 0)), // User Presence
    uv: !!(flagsInt & (1 << 2)), // User Verified
    be: !!(flagsInt & (1 << 3)), // Backup Eligibility
    bs: !!(flagsInt & (1 << 4)), // Backup State
    at: !!(flagsInt & (1 << 6)), // Attested Credential Data Present
    ed: !!(flagsInt & (1 << 7)), // Extension Data Present
  };

  const counter = authData.readUInt32BE(33);
  if (!flags.up) {
    throw new Error("User was not present for authentication");
  }
  if (flags.at) {
    throw new Error("Unexpected attested credential data present in authentication response");
  }
  if (flags.ed) {
    throw new Error("Extension data not supported");
  }

  // Pointer should be at the end of the authenticator data, otherwise too much data was sent
  if (authData.byteLength !== 37) {
    throw new Error('Leftover bytes detected while parsing authenticator data');
  }

  return {
    rpIdHash,
    counter,
  };
}

/**
 * Verify that the user has legitimately completed the login process
 *
 * **Options:**
 *
 * @param response Response returned by **@simplewebauthn/browser**'s `startAssertion()`
 * @param expectedChallenge The base64url-encoded `options.challenge` returned by
 * `generateAuthenticationOptions()`
 * @param expectedOrigin Website URL (or array of URLs) that the registration should have occurred on
 * @param expectedRPID RP ID (or array of IDs) that was specified in the registration options
 * @param expectedType (Optional) The response type expected ('webauthn.get')
 * @param authenticator An internal {@link AuthenticatorDevice} matching the credential's ID
 * @param advancedFIDOConfig (Optional) Options for satisfying more stringent FIDO RP feature
 * requirements
 * @param advancedFIDOConfig.userVerification (Optional) Enable alternative rules for evaluating the
 * User Presence and User Verified flags in authenticator data: UV (and UP) flags are optional
 * unless this value is `"required"`
 */
export async function verifyAuthenticationResponse(
  options: VerifyAuthenticationResponseOpts,
): Promise<VerifiedAuthenticationResponse> {
  const {
    response,
    expectedChallenge,
    expectedOrigin,
    expectedRPID,
    expectedType,
    authenticator,
  } = options;
  const { id, rawId, type: credentialType, response: assertionResponse } = response;

  // Ensure credential specified an ID
  if (!id) {
    throw new Error('Missing credential ID');
  }

  // Ensure ID is base64url-encoded
  if (id !== rawId) {
    throw new Error('Credential ID was not base64url-encoded');
  }

  // Make sure credential type is public-key
  if (credentialType !== 'public-key') {
    throw new Error(
      `Unexpected credential type ${credentialType}, expected "public-key"`,
    );
  }

  if (!response) {
    throw new Error('Credential missing response');
  }

  if (typeof assertionResponse?.clientDataJSON !== 'string') {
    throw new Error('Credential response clientDataJSON was not a string');
  }

  const clientDataJSON = decodeClientDataJSON(assertionResponse.clientDataJSON);

  const { type, origin, challenge, tokenBinding } = clientDataJSON;

  // Make sure we're handling an authentication
  if (Array.isArray(expectedType)) {
    if (!expectedType.includes(type)) {
      const joinedExpectedType = expectedType.join(', ');
      throw new Error(`Unexpected authentication response type "${type}", expected one of: ${joinedExpectedType}`);
    }
  } else if (expectedType) {
    if (type !== expectedType) {
      throw new Error(`Unexpected authentication response type "${type}", expected "${expectedType}"`);
    }
  } else if (type !== 'webauthn.get') {
    throw new Error(`Unexpected authentication response type: ${type}`);
  }

  // Ensure the device provided the challenge we gave it
  if (challenge !== expectedChallenge) {
    throw new Error(
      `Unexpected authentication response challenge "${challenge}", expected "${expectedChallenge}"`,
    );
  }

  // Check that the origin is our site
  if (Array.isArray(expectedOrigin)) {
    if (!expectedOrigin.includes(origin)) {
      const joinedExpectedOrigin = expectedOrigin.join(', ');
      throw new Error(
        `Unexpected authentication response origin "${origin}", expected one of: ${joinedExpectedOrigin}`,
      );
    }
  } else {
    if (origin !== expectedOrigin) {
      throw new Error(
        `Unexpected authentication response origin "${origin}", expected "${expectedOrigin}"`,
      );
    }
  }

  if (
    assertionResponse.userHandle &&
    typeof assertionResponse.userHandle !== 'string'
  ) {
    throw new Error('Credential response userHandle was not a string');
  }

  if (tokenBinding) {
    if (typeof tokenBinding !== 'object') {
      throw new Error('ClientDataJSON tokenBinding was not an object');
    }

    if (
      ['present', 'supported', 'notSupported'].indexOf(tokenBinding.status) < 0
    ) {
      throw new Error(`Unexpected tokenBinding status ${tokenBinding.status}`);
    }
  }

  const authDataBuffer = (
    Buffer.from(b64urldecode(assertionResponse.authenticatorData), "base64")
  );
  const parsedAuthData = parseAuthenticatorData(authDataBuffer);
  const { rpIdHash, counter } = parsedAuthData;

  // Make sure the response's RP ID is ours
  let expectedRPIDs: string[] = [];
  if (typeof expectedRPID === 'string') {
    expectedRPIDs = [expectedRPID];
  } else {
    expectedRPIDs = expectedRPID;
  }

  const matchedRPID = matchExpectedRPID(Buffer.from(rpIdHash), expectedRPIDs);
  if (matchedRPID == null) throw new Error("Unexpected RPID");

	const clientDataHash = crypto.createHash('sha256').update(
    Buffer.from(b64urldecode(assertionResponse.clientDataJSON), "base64")
  ).digest();
  const signatureBase = Buffer.concat([(authDataBuffer), Buffer.from(clientDataHash)]);

  const signature = Buffer.from(b64urldecode(assertionResponse.signature), "base64")

  const cosePublicKey = decodeCredentialPublicKey(authenticator.credentialPublicKey);
  const unwrappedSignature = unwrapEC2Signature(signature);
  const verified = await verifyEC2({
    cosePublicKey,
    signature: unwrappedSignature,
    data: signatureBase,
  });
  const toReturn: VerifiedAuthenticationResponse = {
    verified,
    authenticationInfo: {
      newCounter: counter,
      credentialID: authenticator.credentialID,
      origin: clientDataJSON.origin,
      rpID: matchedRPID,
    },
  };

  return toReturn;
}

/**
 * Result of authentication verification
 *
 * @param verified If the authentication response could be verified
 * @param authenticationInfo.credentialID The ID of the authenticator used during authentication.
 * Should be used to identify which DB authenticator entry needs its `counter` updated to the value
 * below
 * @param authenticationInfo.newCounter The number of times the authenticator identified above
 * reported it has been used. **Should be kept in a DB for later reference to help prevent replay
 * attacks!**
 * @param authenticationInfo.credentialDeviceType Whether this is a single-device or multi-device
 * credential. **Should be kept in a DB for later reference!**
 * @param authenticationInfo.credentialBackedUp Whether or not the multi-device credential has been
 * backed up. Always `false` for single-device credentials. **Should be kept in a DB for later
 * reference!**
 * @param authenticationInfo.origin The origin of the website that the authentication occurred on
 * @param authenticationInfo.rpID The RP ID that the authentication occurred on
 */
export type VerifiedAuthenticationResponse = {
  verified: boolean;
  authenticationInfo: {
    credentialID: Uint8Array;
    newCounter: number;
    origin: string;
    rpID: string;
  };
};
