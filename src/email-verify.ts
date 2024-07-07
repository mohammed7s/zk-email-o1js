import { Field, Bytes, Provable, Poseidon } from 'o1js';
import { Bigint2048, rsaVerify65537 } from 'o1js-rsa';
import { pkcs1v15Pad, bodyHashRegex, selectSubarray } from './utils.js';
import { dynamicSHA256, partialSHA256 } from 'dynamic-sha256';

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
 * @returns - The public key hash.
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
): Field {
  // Hash the email headers // 92675 rows for a 1024-byte input
  const headerHash = dynamicSHA256(paddedHeader, headerHashIndex);
  // PKCS#1 v1.5 encode the hash

  const message = pkcs1v15Pad(headerHash, Math.ceil(modulusLength / 8));

  // Verify RSA65537 signature // 12401 rows
  rsaVerify65537(message, signature, publicKey);

  // 2. Check body hash
  if (bodyHashCheck) {
    // Compute the partial hash of the body // 139074 rows for a 1536-byte input
    const computedBodyHash = partialSHA256(
      precomputedHash,
      paddedBodyRemainingBytes,
      bodyHashIndex
    );

    // Base64 encode the computed body hash // 1697 rows for a 32-byte input
    const encodedBodyHash = computedBodyHash.base64Encode();

    // Reveal the body hash from the email headers using regex // 86453 rows for a 1024-byte input
    const { out, reveal } = bodyHashRegex(paddedHeader.bytes);
    out.assertEquals(1);

    // Select the body hash bytes subarray // 59133 rows for a 1024-byte input
    const headerBodyHash = Bytes.from(
      selectSubarray(reveal[0], headerBodyHashIndex, 44)
    );

    // Assert that the computed body hash matches the regex-fetched body hash from the header
    Provable.assertEqual(encodedBodyHash, headerBodyHash);
  }

  const publickeyhash = Poseidon.hash(publicKey.fields);
  return publickeyhash;
}
