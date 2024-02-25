import * as isoCBOR from './isoCBOR.ts';

/**
 * Convert an AttestationObject buffer to a proper object
 *
 * @param base64AttestationObject Attestation Object buffer
 */
export function decodeAttestationObject(
  attestationObject: Buffer,
): AttestationObject {
  return (
    isoCBOR.decodeFirst<AttestationObject>(attestationObject)
  );
}

export type AttestationFormat =
  | 'fido-u2f'
  | 'packed'
  | 'android-safetynet'
  | 'android-key'
  | 'tpm'
  | 'apple'
  | 'none';

export type AttestationObject = {
  get(key: 'fmt'): AttestationFormat;
  get(key: 'attStmt'): AttestationStatement;
  get(key: 'authData'): Buffer;
};

/**
 * `AttestationStatement` will be an instance of `Map`, but these keys help make finite the list of
 * possible values within it.
 */
export type AttestationStatement = {
  get(key: 'sig'): Buffer | undefined;
  get(key: 'x5c'): Buffer[] | undefined;
  get(key: 'response'): Buffer | undefined;
  get(key: 'alg'): number | undefined;
  get(key: 'ver'): string | undefined;
  get(key: 'certInfo'): Buffer | undefined;
  get(key: 'pubArea'): Buffer | undefined;
  // `Map` properties
  readonly size: number;
};
