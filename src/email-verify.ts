import { Bigint2048, rsaVerify65537 } from 'o1js-rsa';
import { pkcs1v15Pad } from './utils.js';
import { Hash, Bytes, Provable } from 'o1js';
import { base64Decode } from 'o1js-base64';

export { emailVerify };

/**
 * Verifies a DKIM signature using the provided message, signature, and public key.
 *
 * @param {Bytes} headers The message to be verified, represented as a Bytes object.
 * @param {Bigint2048} signature The signature to be verified, represented as a bigint.
 * @param {Bigint2048} publicKey The public key used for verification, represented as a bigint.
 * @returns {void} This function does not return any value.
 */
function emailVerify(
  headers: Bytes,
  signature: bigint,
  publicKey: bigint,
  bodyHashCheck: boolean,
  headerBodyHash: string,
  body: Bytes
) {
  // 1. verify the dkim signature
  let preimageBytes = Bytes(headers.length).from(headers); // convert the preimage to bytes
  let hash = Hash.SHA2_256.hash(preimageBytes); // hash the preimage using o1js
  const modBits = publicKey.toString(2).length; // get emLen : Calculate the length of the encoded message in bytes
  console.log('publicKey', publicKey);
  console.log('modBits', modBits);
  const emLen = Math.ceil(modBits / 8); //
  console.log('emlen', emLen);
  let paddedHash = pkcs1v15Pad(hash, emLen); // pkcs15encode hash
  // convert all to bigint2048
  let final_message = Bigint2048.from(BigInt('0x' + paddedHash.toHex()));
  let final_signature = Bigint2048.from(signature);
  let final_publicKey = Bigint2048.from(publicKey);

  // rsaverify
  rsaVerify65537(final_message, final_signature, final_publicKey);

  // 2. check Body hash
  if (bodyHashCheck == true) {
    const encodedB64 = Bytes.fromString(headerBodyHash);
    const decodedB64 = base64Decode(encodedB64, 32);
    console.log('encodedB64', encodedB64.toBytes());
    console.log('decodedB64', decodedB64.toBytes());
    
    // hash body
    let hashedBody = Hash.SHA2_256.hash(body);
    console.log('hashedBody', hashedBody);
    console.log('hashedBody_bytes', hashedBody.toBytes());
    console.log('hashedBody_hex', hashedBody.toHex());
    Provable.assertEqual(decodedB64, hashedBody);
  }
}
