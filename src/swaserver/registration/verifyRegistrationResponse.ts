import crypto from 'crypto';

import type {
  COSEAlgorithmIdentifier,
  CredentialDeviceType,
  RegistrationResponseJSON,
} from '../deps.ts';
import {
  AttestationFormat,
  AttestationStatement,
  decodeAttestationObject,
} from '../helpers/decodeAttestationObject.ts';
import { AuthenticationExtensionsAuthenticatorOutputs } from '../helpers/decodeAuthenticatorExtensions.ts';
import { decodeClientDataJSON } from '../helpers/decodeClientDataJSON.ts';
import { parseAuthenticatorData } from '../helpers/parseAuthenticatorData.ts';
import { decodeCredentialPublicKey } from '../helpers/decodeCredentialPublicKey.ts';
import { COSEKEYS } from '../helpers/cose.ts';
import { convertAAGUIDToString } from '../helpers/convertAAGUIDToString.ts';
import { parseBackupFlags } from '../helpers/parseBackupFlags.ts';
import { matchExpectedRPID } from '../helpers/matchExpectedRPID.ts';

import { supportedCOSEAlgorithmIdentifiers } from './generateRegistrationOptions.ts';
import { verifyAttestationFIDOU2F } from './verifications/verifyAttestationFIDOU2F.ts';
import { b64urldecode } from '../../shared.ts';

export type VerifyRegistrationResponseOpts = {
  response: RegistrationResponseJSON;
  expectedChallenge: string[];
  expectedOrigin: string[];
  expectedRPID: string[];
  requireUserVerification?: boolean;
  supportedAlgorithmIDs?: COSEAlgorithmIdentifier[];
};

/**
 * Verify that the user has legitimately completed the registration process
 *
 * **Options:**
 *
 * @param response Response returned by **@simplewebauthn/browser**'s `startAuthentication()`
 * @param expectedChallenge The base64url-encoded `options.challenge` returned by
 * `generateRegistrationOptions()`
 * @param expectedOrigin Website URL (or array of URLs) that the registration should have occurred on
 * @param expectedRPID RP ID (or array of IDs) that was specified in the registration options
 * @param expectedType (Optional) The response type expected ('webauthn.create')
 * @param requireUserVerification (Optional) Enforce user verification by the authenticator
 * (via PIN, fingerprint, etc...)
 * @param supportedAlgorithmIDs Array of numeric COSE algorithm identifiers supported for
 * attestation by this RP. See https://www.iana.org/assignments/cose/cose.xhtml#algorithms
 */
export async function verifyRegistrationResponse(
  options: VerifyRegistrationResponseOpts,
): Promise<VerifiedRegistrationResponse> {
  const {
    response,
    expectedChallenge,
    expectedOrigin,
    expectedRPID,
    requireUserVerification = true,
    supportedAlgorithmIDs = supportedCOSEAlgorithmIdentifiers,
  } = options;
  const { id, rawId, type: credentialType, response: attestationResponse } = response;

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

  const clientDataJSON = decodeClientDataJSON(
    attestationResponse.clientDataJSON,
  );

  const { type, origin, challenge, tokenBinding } = clientDataJSON;

  // Make sure we're handling an registration
  if (type !== 'webauthn.create') {
    throw new Error(`Unexpected registration response type: ${type}`);
  }

  // Ensure the device provided the challenge we gave it
  if (!expectedChallenge.includes(challenge)) {
    throw new Error(
      "Wrong registration response challenge",
    );
  }

  // Check that the origin is our site
  if (Array.isArray(expectedOrigin)) {
    if (!expectedOrigin.includes(origin)) {
      throw new Error(
        `Unexpected registration response origin "${origin}", expected one of: ${
          expectedOrigin.join(
            ', ',
          )
        }`,
      );
    }
  }

  if (tokenBinding) {
    if (typeof tokenBinding !== 'object') {
      throw new Error(`Unexpected value for TokenBinding "${tokenBinding}"`);
    }

    if (
      ['present', 'supported', 'not-supported'].indexOf(tokenBinding.status) < 0
    ) {
      throw new Error(
        `Unexpected tokenBinding.status value of "${tokenBinding.status}"`,
      );
    }
  }

  const attestationObject = Buffer.from(b64urldecode(attestationResponse.attestationObject), "base64")
  const decodedAttestationObject = decodeAttestationObject(attestationObject);
  const fmt = decodedAttestationObject.get('fmt');
  const authData = decodedAttestationObject.get('authData');
  const attStmt = decodedAttestationObject.get('attStmt');

  const parsedAuthData = parseAuthenticatorData(authData);
  const {
    aaguid,
    rpIdHash,
    flags,
    credentialID,
    counter,
    credentialPublicKey,
    extensionsData,
  } = parsedAuthData;

  // Make sure the response's RP ID is ours
  let matchedRPID = matchExpectedRPID(Buffer.from(rpIdHash), expectedRPID);
  if (matchedRPID == null) throw new Error("Unexpected RPID");

  // Make sure someone was physically present
  if (!flags.up) {
    throw new Error('User not present during registration');
  }

  // Enforce user verification if specified
  if (requireUserVerification && !flags.uv) {
    throw new Error(
      'User verification required, but user could not be verified',
    );
  }

  if (!credentialID) {
    throw new Error('No credential ID was provided by authenticator');
  }

  if (!credentialPublicKey) {
    throw new Error('No public key was provided by authenticator');
  }

  if (!aaguid) {
    throw new Error('No AAGUID was present during registration');
  }

  const decodedPublicKey = decodeCredentialPublicKey(credentialPublicKey);
  const alg = decodedPublicKey.get(COSEKEYS.alg);

  if (typeof alg !== 'number') {
    throw new Error('Credential public key was missing numeric alg');
  }

  // Make sure the key algorithm is one we specified within the registration options
  if (!supportedAlgorithmIDs.includes(alg as number)) {
    const supported = supportedAlgorithmIDs.join(', ');
    throw new Error(
      `Unexpected public key alg "${alg}", expected one of "${supported}"`,
    );
  }

  const clientDataHash = crypto.createHash('sha256').update(
    Buffer.from(b64urldecode(attestationResponse.clientDataJSON), "base64"),
  ).digest();

  // Prepare arguments to pass to the relevant verification method
  const verifierOpts: AttestationFormatVerifierOpts = {
    aaguid,
    attStmt,
    authData,
    clientDataHash,
    credentialID: Buffer.from(credentialID),
    credentialPublicKey,
    rpIdHash: Buffer.from(rpIdHash),
  };

  if (fmt !== 'fido-u2f') {
    throw new Error(`Unsupported Attestation Format: ${fmt}`);
  }
  const verified = await verifyAttestationFIDOU2F(verifierOpts);
  if (!verified) return {verified: false};

  const { credentialDeviceType, credentialBackedUp } = parseBackupFlags(
    flags,
  );

  return {
    verified: true,
    registrationInfo: {
      fmt,
      counter,
      aaguid: convertAAGUIDToString(aaguid),
      credentialID,
      credentialPublicKey,
      credentialType,
      attestationObject,
      userVerified: flags.uv,
      credentialDeviceType,
      credentialBackedUp,
      origin: clientDataJSON.origin,
      rpID: matchedRPID,
      authenticatorExtensionResults: extensionsData,
    },
  };
}

/**
 * Result of registration verification
 *
 * @param verified If the assertion response could be verified
 * @param registrationInfo.fmt Type of attestation
 * @param registrationInfo.counter The number of times the authenticator reported it has been used.
 * **Should be kept in a DB for later reference to help prevent replay attacks!**
 * @param registrationInfo.aaguid Authenticator's Attestation GUID indicating the type of the
 * authenticator
 * @param registrationInfo.credentialPublicKey The credential's public key
 * @param registrationInfo.credentialID The credential's credential ID for the public key above
 * @param registrationInfo.credentialType The type of the credential returned by the browser
 * @param registrationInfo.userVerified Whether the user was uniquely identified during attestation
 * @param registrationInfo.attestationObject The raw `response.attestationObject` Buffer returned by
 * the authenticator
 * @param registrationInfo.credentialDeviceType Whether this is a single-device or multi-device
 * credential. **Should be kept in a DB for later reference!**
 * @param registrationInfo.credentialBackedUp Whether or not the multi-device credential has been
 * backed up. Always `false` for single-device credentials. **Should be kept in a DB for later
 * reference!**
 * @param registrationInfo.origin The origin of the website that the registration occurred on
 * @param registrationInfo?.rpID The RP ID that the registration occurred on, if one or more were
 * specified in the registration options
 * @param registrationInfo?.authenticatorExtensionResults The authenticator extensions returned
 * by the browser
 */
export type VerifiedRegistrationResponse = {
  verified: boolean;
  registrationInfo?: {
    fmt: AttestationFormat;
    counter: number;
    aaguid: string;
    credentialID: Uint8Array;
    credentialPublicKey: Uint8Array;
    credentialType: 'public-key';
    attestationObject: Uint8Array;
    userVerified: boolean;
    credentialDeviceType: CredentialDeviceType;
    credentialBackedUp: boolean;
    origin: string;
    rpID?: string;
    authenticatorExtensionResults?: AuthenticationExtensionsAuthenticatorOutputs;
  };
};

/**
 * Values passed to all attestation format verifiers, from which they are free to use as they please
 */
export type AttestationFormatVerifierOpts = {
  aaguid: Uint8Array;
  attStmt: AttestationStatement;
  authData: Uint8Array;
  clientDataHash: Buffer;
  credentialID: Buffer;
  credentialPublicKey: Uint8Array;
  rpIdHash: Buffer;
  verifyTimestampMS?: boolean;
};
