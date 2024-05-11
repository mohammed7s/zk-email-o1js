import { Bytes } from 'o1js';

export { pkcs1v15Pad };

/**
 * Creates a PKCS#1 v1.5 padded signature for the given SHA-256 digest.
 * 
 * @note This function follows the RFC3447 standard: https://datatracker.ietf.org/doc/html/rfc3447#section-9.2
 * 
 * @param sha256Digest The SHA-256 digest to be padded.
 * @param modulusLength The size of the RSA modulus in bytes.
 * @returns The padded PKCS#1 v1.5 signature.
 */
function pkcs1v15Pad(sha256Digest: Bytes, modulusLength: number): Bytes {
  // Parse the PKCS#1 v1.5 algorithm constant
  const algorithmConstantBytes = Bytes.fromHex(
    '3031300d060960864801650304020105000420'
  ).bytes;

  // Calculate the length of the padding string (PS)
  const padLength =
    modulusLength - sha256Digest.length - algorithmConstantBytes.length - 3;

  // Create the padding string (PS) with 0xFF bytes based on padLength 
  const paddingString = Bytes.from(new Array(padLength).fill(0xff));

  // Assemble the PKCS#1 v1.5 padding components
  const padding = [
    ...Bytes.fromHex('0001').bytes,       // Block type (BT)
    ...paddingString.bytes,               // Padding string (PS)
    ...Bytes.fromHex('00').bytes,         // Separator (00)
    ...algorithmConstantBytes,            // Algorithm identifier (OID)
    ...sha256Digest.bytes,                // SHA-256 digest
  ];

  // Return the padded PKCS#1 v1.5 signature
  return Bytes.from(padding);
}