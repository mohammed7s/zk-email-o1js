import { Bigint2048, rsaVerify65537 } from 'o1js-rsa';
import { pkcs1v15Pad } from './utils.js';
import { Hash, Bytes, Provable } from 'o1js';
import { base64Decode } from 'o1js-base64';

export { emailVerify };

/**
 * Verifies a DKIM signature using the provided message, signature, and public key.
 *
 * @param headers - The message to be verified, represented as a Bytes object.
 * @param signature - The signature to be verified.
 * @param publicKey - The public key used for verification.
 * @param modulusLength - The length of the modulus.
 * @param bodyHashCheck - Indicates whether to check the body hash.
 * @param headerBodyHash - The hash of the header and body.
 * @param body - The body of the email.
 */
function emailVerify(
  headers: Bytes,
  signature: Bigint2048,
  publicKey: Bigint2048,
  modulusLength: number,
  bodyHashCheck: boolean,
  headerBodyHash: Bytes,
  body: Bytes
) {
  // 1. Verify the DKIM signature
  const hash = Hash.SHA2_256.hash(headers); // Hash the preimage using o1js
  const paddedHash = pkcs1v15Pad(hash, Math.ceil(modulusLength / 8)); // PKCS#1 v1.5 encode the hash

  // Create message for verification
  const message = Provable.witness(Bigint2048, () => {
    const hexString = '0x' + paddedHash.toHex();
    return Bigint2048.from(BigInt(hexString));
  });

  // Verify RSA65537 signature
  rsaVerify65537(message, signature, publicKey);

  // 2. Check body hash
  if (bodyHashCheck) {
    // Decode base64-encoded body hash
    const decodedB64 = base64Decode(headerBodyHash, 32);

    // Hash body
    const hashedBody = Hash.SHA2_256.hash(body);
    Provable.assertEqual(decodedB64, hashedBody);
  }
}
