import { webcrypto } from 'crypto';

import { COSECRV, COSEKEYS, COSEPublicKeyEC2 } from './cose.ts';
import { b64urlencode } from '../../shared.ts';

/**
 * Verify a signature using an EC2 public key
 */
export async function verifyEC2(opts: {
  cosePublicKey: COSEPublicKeyEC2;
  signature: Buffer;
  data: Buffer;
}): Promise<boolean> {
  const { cosePublicKey, signature, data } = opts;

  // Import the public key
  const alg = cosePublicKey.get(COSEKEYS.alg);
  const crv = cosePublicKey.get(COSEKEYS.crv);
  const x = cosePublicKey.get(COSEKEYS.x);
  const y = cosePublicKey.get(COSEKEYS.y);

  if (!alg) {
    throw new Error('Public key was missing alg (EC2)');
  }

  if (!crv) {
    throw new Error('Public key was missing crv (EC2)');
  }

  if (!x) {
    throw new Error('Public key was missing x (EC2)');
  }

  if (!y) {
    throw new Error('Public key was missing y (EC2)');
  }

  if (crv !== COSECRV.P256) {
    throw new Error(`Unexpected COSE crv value of ${crv} (EC2)`);
  }

  const keyData: JsonWebKey = {
    kty: 'EC',
    crv: 'P-256',
    x: b64urlencode(Buffer.from(x).toString("base64")),
    y: b64urlencode(Buffer.from(y).toString("base64")),
    ext: false,
  };

  const keyAlgorithm: EcKeyImportParams = {
    /**
     * Note to future self: you can't use `mapCoseAlgToWebCryptoKeyAlgName()` here because some
     * leaf certs from actual devices specified an RSA SHA value for `alg` (e.g. `-257`) which
     * would then map here to `'RSASSA-PKCS1-v1_5'`. We always want `'ECDSA'` here so we'll
     * hard-code this.
     */
    name: 'ECDSA',
    namedCurve: 'P-256',
  };

  const key = await webcrypto.subtle.importKey('jwk', keyData, keyAlgorithm, false, [
    'verify',
  ]);

  const verifyAlgorithm: EcdsaParams = {
    name: 'ECDSA',
    hash: { name: 'SHA-256' },
  };

  return webcrypto.subtle.verify(verifyAlgorithm, key, signature, data);
}
