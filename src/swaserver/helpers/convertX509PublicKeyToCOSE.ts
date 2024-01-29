import {
  AsnParser,
  Certificate,
  ECParameters,
  id_ecPublicKey,
  id_secp256r1,
  id_secp384r1,
} from '../deps.ts';
import {
  COSECRV,
  COSEKEYS,
  COSEKTY,
  COSEPublicKeyEC2,
} from './cose.ts';
import { mapX509SignatureAlgToCOSEAlg } from './mapX509SignatureAlgToCOSEAlg.ts';

export function convertX509PublicKeyToCOSE(
  x509Certificate: Uint8Array,
): COSEPublicKeyEC2 {
  /**
   * Time to extract the public key from an X.509 certificate
   */
  const x509 = AsnParser.parse(x509Certificate, Certificate);

  const { tbsCertificate } = x509;
  const { subjectPublicKeyInfo, signature: _tbsSignature } = tbsCertificate;

  const signatureAlgorithm = _tbsSignature.algorithm;
  const publicKeyAlgorithmID = subjectPublicKeyInfo.algorithm.algorithm;

  if (publicKeyAlgorithmID === id_ecPublicKey) {
    /**
     * EC2 Public Key
     */
    if (!subjectPublicKeyInfo.algorithm.parameters) {
      throw new Error('Certificate public key was missing parameters (EC2)');
    }

    const ecParameters = AsnParser.parse(
      new Uint8Array(subjectPublicKeyInfo.algorithm.parameters),
      ECParameters,
    );

    let crv = -999;
    const { namedCurve } = ecParameters;

    if (namedCurve === id_secp256r1) {
      crv = COSECRV.P256;
    } else if (namedCurve === id_secp384r1) {
      crv = COSECRV.P384;
    } else {
      throw new Error(
        `Certificate public key contained unexpected namedCurve ${namedCurve} (EC2)`,
      );
    }

    const subjectPublicKey = new Uint8Array(
      subjectPublicKeyInfo.subjectPublicKey,
    );

    let x: Uint8Array;
    let y: Uint8Array;
    if (subjectPublicKey[0] === 0x04) {
      // Public key is in "uncompressed form", so we can split the remaining bytes in half
      let pointer = 1;
      const halfLength = (subjectPublicKey.length - 1) / 2;
      x = subjectPublicKey.slice(pointer, pointer += halfLength);
      y = subjectPublicKey.slice(pointer);
    } else {
      throw new Error(
        'TODO: Figure out how to handle public keys in "compressed form"',
      );
    }

    const coseEC2PubKey: COSEPublicKeyEC2 = new Map();
    coseEC2PubKey.set(COSEKEYS.kty, COSEKTY.EC2);
    coseEC2PubKey.set(
      COSEKEYS.alg,
      mapX509SignatureAlgToCOSEAlg(signatureAlgorithm),
    );
    coseEC2PubKey.set(COSEKEYS.crv, crv);
    coseEC2PubKey.set(COSEKEYS.x, x);
    coseEC2PubKey.set(COSEKEYS.y, y);

    return coseEC2PubKey;
  }
  throw new Error(
    `Certificate public key contained unexpected algorithm ID ${publicKeyAlgorithmID}`,
  );
}
