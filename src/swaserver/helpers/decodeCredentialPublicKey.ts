import { COSEKEYS, COSEPublicKey, COSEPublicKeyEC2, isCOSEPublicKeyEC2 } from './cose.ts';
import { isoCBOR } from './iso/index.ts';

export function decodeCredentialPublicKey(
  publicKey: Uint8Array,
): COSEPublicKeyEC2 {
  const cosePublicKey = isoCBOR.decodeFirst<COSEPublicKey>(publicKey);
  if (!isCOSEPublicKeyEC2(cosePublicKey)) {
    const kty = cosePublicKey.get(COSEKEYS.kty);
    throw new Error(
      `Signature verification with public key of kty ${kty} is not supported by this method`,
    );
  }
  return cosePublicKey;
}
