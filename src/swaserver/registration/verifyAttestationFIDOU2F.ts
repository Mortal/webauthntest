import type { AttestationFormatVerifierOpts } from './verifyRegistrationResponse.ts';

import { convertX509PublicKeyToCOSE } from '../helpers/convertX509PublicKeyToCOSE.ts';
import { unwrapEC2Signature } from '../helpers/unwrapEC2Signature.ts';
import { verifyEC2 } from '../helpers/verifyEC2.ts';
import * as isoCBOR from '../helpers/isoCBOR.ts';
import { COSEKEYS, COSEPublicKeyEC2 } from '../helpers/cose.ts';

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
