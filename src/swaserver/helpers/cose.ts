/**
 * Fundamental values that are needed to discern the more specific COSE public key types below.
 *
 * The use of `Maps` here is due to CBOR encoding being used with public keys, and the CBOR "Map"
 * type is being decoded to JavaScript's `Map` type instead of, say, a basic Object as us JS
 * developers might prefer.
 *
 * These types are an unorthodox way of saying "these Maps should involve these discrete lists of
 * keys", but it works.
 */
export type COSEPublicKey = {
  // Getters
  get(key: COSEKEYS.kty): COSEKTY | undefined;
  get(key: COSEKEYS.alg): COSEALG | undefined;
  // Setters
  set(key: COSEKEYS.kty, value: COSEKTY): void;
  set(key: COSEKEYS.alg, value: COSEALG): void;
};

export type COSEPublicKeyEC2 = COSEPublicKey & {
  // Getters
  get(key: COSEKEYS.crv): number | undefined;
  get(key: COSEKEYS.x): Uint8Array | undefined;
  get(key: COSEKEYS.y): Uint8Array | undefined;
  // Setters
  set(key: COSEKEYS.crv, value: number): void;
  set(key: COSEKEYS.x, value: Uint8Array): void;
  set(key: COSEKEYS.y, value: Uint8Array): void;
};

export function isCOSEPublicKeyEC2(
  cosePublicKey: COSEPublicKey,
): cosePublicKey is COSEPublicKeyEC2 {
  const kty = cosePublicKey.get(COSEKEYS.kty);
  return kty === 2;
}

/**
 * COSE Keys
 *
 * https://www.iana.org/assignments/cose/cose.xhtml#key-common-parameters
 * https://www.iana.org/assignments/cose/cose.xhtml#key-type-parameters
 */
export enum COSEKEYS {
  kty = 1,
  alg = 3,
  crv = -1,
  x = -2,
  y = -3,
  n = -1,
  e = -2,
}

/**
 * COSE Key Types
 *
 * https://www.iana.org/assignments/cose/cose.xhtml#key-type
 */
export enum COSEKTY {
  OKP = 1,
  EC2 = 2,
  RSA = 3,
}

/**
 * COSE Curves
 *
 * https://www.iana.org/assignments/cose/cose.xhtml#elliptic-curves
 */
export enum COSECRV {
  P256 = 1,
  P384 = 2,
  P521 = 3,
  ED25519 = 6,
  SECP256K1 = 8,
}

/**
 * COSE Algorithms
 *
 * https://www.iana.org/assignments/cose/cose.xhtml#algorithms
 */
export enum COSEALG {
  ES256 = -7,
  EdDSA = -8,
  ES384 = -35,
  ES512 = -36,
  PS256 = -37,
  PS384 = -38,
  PS512 = -39,
  ES256K = -47,
  RS256 = -257,
  RS384 = -258,
  RS512 = -259,
  RS1 = -65535,
}

/**
 * Map X.509 signature algorithm OIDs to COSE algorithm IDs
 *
 * - EC2 OIDs: https://oidref.com/1.2.840.10045.4.3
 * - RSA OIDs: https://oidref.com/1.2.840.113549.1.1
 */
export function mapX509SignatureAlgToCOSEAlg(
  signatureAlgorithm: string,
): COSEALG {
  let alg: COSEALG;

  if (signatureAlgorithm === '1.2.840.10045.4.3.2') {
    alg = COSEALG.ES256;
  } else if (signatureAlgorithm === '1.2.840.10045.4.3.3') {
    alg = COSEALG.ES384;
  } else if (signatureAlgorithm === '1.2.840.10045.4.3.4') {
    alg = COSEALG.ES512;
  } else if (signatureAlgorithm === '1.2.840.113549.1.1.11') {
    alg = COSEALG.RS256;
  } else if (signatureAlgorithm === '1.2.840.113549.1.1.12') {
    alg = COSEALG.RS384;
  } else if (signatureAlgorithm === '1.2.840.113549.1.1.13') {
    alg = COSEALG.RS512;
  } else if (signatureAlgorithm === '1.2.840.113549.1.1.5') {
    alg = COSEALG.RS1;
  } else {
    throw new Error(
      `Unable to map X.509 signature algorithm ${signatureAlgorithm} to a COSE algorithm`,
    );
  }

  return alg;
}
