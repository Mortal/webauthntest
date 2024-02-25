import crypto from 'crypto';

import type {
  COSEAlgorithmIdentifier,
  RegistrationResponseJSON,
} from '../../swatypes/index.ts';
import {
  AttestationFormat,
  AttestationStatement,
  decodeAttestationObject,
} from '../helpers/decodeAttestationObject.ts';
import { decodeClientDataJSON } from '../helpers/decodeClientDataJSON.ts';
import { decodeCredentialPublicKey } from '../helpers/decodeCredentialPublicKey.ts';
import { COSEKEYS, COSEPublicKeyEC2 } from '../helpers/cose.ts';
import { matchExpectedRPID } from '../helpers/matchExpectedRPID.ts';
import * as isoCBOR from '../helpers/isoCBOR.ts';
import { COSEPublicKey } from '../helpers/cose.ts';
import { convertX509PublicKeyToCOSE } from '../helpers/convertX509PublicKeyToCOSE.ts';
import { unwrapEC2Signature } from '../helpers/unwrapEC2Signature.ts';
import { verifyEC2 } from '../helpers/verifyEC2.ts';

import { supportedCOSEAlgorithmIdentifiers } from './generateRegistrationOptions.ts';
import { b64urldecode } from '../../shared.ts';

export type VerifyRegistrationResponseOpts = {
  response: RegistrationResponseJSON;
  expectedChallenge: string[];
  expectedOrigin: string[];
  expectedRPID: string[];
  supportedAlgorithmIDs?: COSEAlgorithmIdentifier[];
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
    flagsInt,
  };

  const counterBuf = authData.subarray(33, 37);
  const counter = authData.readUInt32BE(33);
  if (!flags.at) {
    throw new Error("No attested credential data present");
  }
  const aaguid = authData.subarray(37, 53);
  const credIDLen = authData.readUInt16BE(53);
  const credentialID = authData.subarray(55, 55 + credIDLen);

  // Decode the next CBOR item in the buffer, then re-encode it back to a Buffer
  const firstDecoded = isoCBOR.decodeFirst<COSEPublicKey>(
    authData.subarray(55 + credIDLen),
  );
  const credentialPublicKey = Buffer.from(isoCBOR.encode(firstDecoded));

  if (flags.ed) {
    throw new Error("Extension data not supported");
  }

  // Pointer should be at the end of the authenticator data, otherwise too much data was sent
  if (authData.byteLength !== 55 + credIDLen + credentialPublicKey.byteLength) {
    throw new Error('Leftover bytes detected while parsing authenticator data');
  }

  // Make sure someone was physically present
  if (!flags.up) {
    throw new Error('User not present during registration');
  }

  return {
    rpIdHash,
    flags,
    counter,
    counterBuf,
    aaguid,
    credentialID,
    credentialPublicKey,
  };
}

/**
 * Convert the aaguid buffer in authData into a UUID string
 */
function convertAAGUIDToString(aaguid: Uint8Array): string {
  // Raw Hex: adce000235bcc60a648b0b25f1f05503
  const hex = Buffer.from(aaguid).toString("hex");

  const segments: string[] = [
    hex.slice(0, 8), // 8
    hex.slice(8, 12), // 4
    hex.slice(12, 16), // 4
    hex.slice(16, 20), // 4
    hex.slice(20, 32), // 8
  ];

  // Formatted: adce0002-35bc-c60a-648b-0b25f1f05503
  return segments.join('-');
}

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
    credentialID,
    counter,
    credentialPublicKey,
  } = parsedAuthData;

  // Make sure the response's RP ID is ours
  let matchedRPID = matchExpectedRPID(Buffer.from(rpIdHash), expectedRPID);
  if (matchedRPID == null) throw new Error("Unexpected RPID");

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
      origin: clientDataJSON.origin,
      rpID: matchedRPID,
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
    origin: string;
    rpID?: string;
  };
};

/**
 * Values passed to all attestation format verifiers, from which they are free to use as they please
 */
export type AttestationFormatVerifierOpts = {
  aaguid: Buffer;
  attStmt: AttestationStatement;
  authData: Buffer;
  clientDataHash: Buffer;
  credentialID: Buffer;
  credentialPublicKey: Buffer;
  rpIdHash: Buffer;
  verifyTimestampMS?: boolean;
};

/**
 * Takes COSE-encoded public key and converts it to PKCS key
 */
function convertCOSEtoPKCS(cosePublicKey: Buffer) {
  const struct = isoCBOR.decodeFirst<COSEPublicKeyEC2>(cosePublicKey);

  const tag = Buffer.from([0x04]);
  const x = struct.get(COSEKEYS.x);
  const y = struct.get(COSEKEYS.y);

  if (!x) {
    throw new Error('COSE public key was missing x');
  }
  if (!y) {
    throw new Error('COSE public key was missing y');
  }
  return Buffer.concat([tag, x, y]);
}

/**
 * Verify an attestation response with fmt 'fido-u2f'
 */
export async function verifyAttestationFIDOU2F(
  options: AttestationFormatVerifierOpts,
): Promise<boolean> {
  const {
    attStmt,
    clientDataHash,
    rpIdHash,
    credentialID,
    credentialPublicKey,
    aaguid,
  } = options;

  const reservedByte = Buffer.from([0x00]);
  const publicKey = convertCOSEtoPKCS(credentialPublicKey);

  const signatureBase = Buffer.concat([
    reservedByte,
    rpIdHash,
    clientDataHash,
    credentialID,
    publicKey,
  ]);

  const sig = attStmt.get('sig');
  const x5c = attStmt.get('x5c');

  if (!x5c) {
    throw new Error(
      'No attestation certificate provided in attestation statement (FIDOU2F)',
    );
  }
  if (x5c.length > 1) {
    throw new Error(
      'Certificate chain validation is not supported',
    );
  }

  if (!sig) {
    throw new Error(
      'No attestation signature provided in attestation statement (FIDOU2F)',
    );
  }

  // FIDO spec says that aaguid _must_ equal 0x00 here to be legit
  const aaguidToHex = aaguid[0];
  if (aaguidToHex !== 0x00) {
    throw new Error(`AAGUID "${aaguidToHex}" was not expected value`);
  }

  const cosePublicKey = convertX509PublicKeyToCOSE(x5c[0]);
  const unwrappedSignature = unwrapEC2Signature(sig);
  return verifyEC2({
    cosePublicKey,
    signature: unwrappedSignature,
    data: signatureBase,
  });
}
