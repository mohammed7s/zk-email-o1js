import { Field, Bytes, Provable } from 'o1js';
import { Bigint2048, rsaVerify65537 } from 'o1js-rsa';
import { pkcs1v15Pad, bodyHashRegex, selectSubarray } from './utils.js';
import { dynamicSHA256, partialSHA256 } from 'sha256-dynamic';

export { emailVerify };

/**
 * Verifies a DKIM signature using the provided message, signature, and public key.
 *
 * This function hashes the headers, encodes the hash using PKCS#1 v1.5, and verifies the RSA signature.
 * If required, it also checks the body hash against the one provided in the email headers.
 *
 * @param paddedHeader - The padded header as Bytes to be verified.
 * @param headerHashIndex - The index of the header hash within the padded header as Field.
 * @param signature - The signature to be verified as Bigint2048.
 * @param publicKey - The public key used for verification as Bigint2048.
 * @param modulusLength - The length of the RSA modulus.
 * @param bodyHashCheck - Boolean indicating whether to check the body hash.
 * @param paddedBodyRemainingBytes - The remaining padded body bytes as Bytes.
 * @param precomputedHash - The precomputed hash as Bytes.
 * @param bodyHashIndex - The index of the body hash within the headers as Field.
 * @param headerBodyHashIndex - The index of the body hash within the header hash as Field.
 */
function emailVerify(
  paddedHeader: Bytes,
  headerHashIndex: Field,
  signature: Bigint2048,
  publicKey: Bigint2048,
  modulusLength: number,
  bodyHashCheck: boolean,
  paddedBodyRemainingBytes: Bytes,
  precomputedHash: Bytes,
  bodyHashIndex: Field,
  headerBodyHashIndex: Field
) {
  // Hash the email headers
  const headerHash = dynamicSHA256(paddedHeader, headerHashIndex); // Hash the headers using o1js
  const paddedHash = pkcs1v15Pad(headerHash, Math.ceil(modulusLength / 8)); // PKCS#1 v1.5 encode the hash

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
    const computedBodyHash = partialSHA256(
      precomputedHash,
      paddedBodyRemainingBytes,
      bodyHashIndex
    );

    // Base64 encode the computed body hash
    const encodedBodyHash = computedBodyHash.base64Encode();

    // Reveal the body hash from the email headers using regex
    const { out, reveal } = bodyHashRegex(paddedHeader.bytes);
    out.assertEquals(1);

    // Select the body hash bytes subarray
    const headerBodyHash = Bytes.from(
      selectSubarray(reveal[0], headerBodyHashIndex, 44)
    );

    // Assert that the computed body hash matches the regex-fetched body hash from the header
    Provable.assertEqual(encodedBodyHash, headerBodyHash);
  }
}
