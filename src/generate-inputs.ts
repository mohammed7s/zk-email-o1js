import { Bytes } from 'o1js';
import { Bigint2048 } from 'o1js-rsa';
import { verifyDKIMSignature } from '@zk-email/helpers/dist/dkim/index.js';

export { generateInputs, EmailVerifyInputs };

type EmailVerifyInputs = {
  headers: Bytes;
  signature: Bigint2048;
  publicKey: Bigint2048;
  modulusLength: number;
  headerBodyHash: Bytes;
  body: Bytes;
};

/**
 * Generates inputs required for email verification from a raw email string.
 *
 * @param rawEmail The raw email string.
 * @returns The email verification inputs.
 */
async function generateInputs(rawEmail: string): Promise<EmailVerifyInputs> {
  // Parse raw email and retrieve public key of the domain in header
  const dkimResult = await verifyDKIMSignature(Buffer.from(rawEmail));
  console.log('DKIM result:', dkimResult);
  // console.log('DKIM headers length:', dkimResult);

  // Extract components from DKIM result
  const headers = Bytes.from(dkimResult.headers);
  const signature = Bigint2048.from(dkimResult.signature);
  const publicKey = Bigint2048.from(dkimResult.publicKey);

  const modulusLength = dkimResult.modulusLength;

  const headerBodyHash = Bytes.fromString(dkimResult.bodyHash);
  const body = Bytes.from(new Uint8Array(dkimResult.body));

  return { headers, signature, publicKey, modulusLength, headerBodyHash, body };
}
