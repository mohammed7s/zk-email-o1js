import { Bigint2048, rsaVerify65537 } from 'o1js-rsa';
import { pkcs1v15Pad, bodyHashRegex, selectSubarray } from './utils.js';
import { Field, Hash, Bytes, Provable } from 'o1js';

export { emailVerify };

/**
 * Verifies a DKIM signature using the provided message, signature, and public key.
 *
 * @param headers - The email headers to be verified.
 * @param signature - The signature to be verified.
 * @param publicKey - The public key used for verification.
 * @param modulusLength - The length of the modulus.
 * @param bodyHashCheck - Indicates whether to check the body hash.
 * @param bodyHashIndex - The index of the body hash inside the headers.
 * @param body - The body of the email.
 */
function emailVerify(
  headers: Bytes,
  signature: Bigint2048,
  publicKey: Bigint2048,
  modulusLength: number,
  bodyHashCheck: boolean,
  bodyHashIndex: Field,
  body: Bytes
) {
  // 1. Verify the DKIM signature
  const hash = Hash.SHA2_256.hash(headers); // Hash the headers using o1js
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
    // Hash the body
    const hashedBody = Hash.SHA2_256.hash(body);

    // Base64 encode the computed body hash
    const encodedBodyHash = hashedBody.base64Encode();

    // Reveal the body hash from the email headers using regex
    const { out, reveal } = bodyHashRegex(headers.bytes);
    out.assertEquals(1);

    // Select the body hash bytes subarray
    const headerBodyHash = Bytes.from(
      selectSubarray(reveal[0], bodyHashIndex, 44)
    );

    // Assert that the computed body hash matches the header body hash
    Provable.assertEqual(encodedBodyHash, headerBodyHash);
  }
}
