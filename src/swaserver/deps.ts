// @simplewebauthn/types
export type {
  AttestationConveyancePreference,
  AuthenticationExtensionsClientInputs,
  AuthenticationResponseJSON,
  AuthenticatorDevice,
  AuthenticatorSelectionCriteria,
  Base64URLString,
  COSEAlgorithmIdentifier,
  CredentialDeviceType,
  Crypto,
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialDescriptorFuture,
  PublicKeyCredentialParameters,
  PublicKeyCredentialRequestOptionsJSON,
  RegistrationResponseJSON,
  UserVerificationRequirement,
} from '../swatypes/index.ts';

// cbor (a.k.a. cbor-x in Node land)
export * as cborx from 'cbor-x';

// b64 (a.k.a. @hexagon/base64 in Node land)
// export { default as base64 } from '@hexagon/base64';

// cross-fetch
// export { fetch as crossFetch } from 'https://esm.sh/cross-fetch@4.0.0';

// @peculiar libraries
export { AsnParser, AsnSerializer } from '@peculiar/asn1-schema';
export {
  AuthorityKeyIdentifier,
  BasicConstraints,
  Certificate,
  CertificateList,
  CRLDistributionPoints,
  ExtendedKeyUsage,
  id_ce_authorityKeyIdentifier,
  id_ce_basicConstraints,
  id_ce_cRLDistributionPoints,
  id_ce_extKeyUsage,
  id_ce_subjectAltName,
  id_ce_subjectKeyIdentifier,
  Name,
  SubjectAlternativeName,
  SubjectKeyIdentifier,
} from '@peculiar/asn1-x509';
export {
  ECDSASigValue,
  ECParameters,
  id_ecPublicKey,
  id_secp256r1,
  id_secp384r1,
} from '@peculiar/asn1-ecc';
