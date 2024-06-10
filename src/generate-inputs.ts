import { Field, Bytes } from 'o1js';
import { Bigint2048 } from 'o1js-rsa';
import { verifyDKIMSignature } from '@zk-email/helpers/dist/dkim/index.js';

export { generateInputs, EmailVerifyInputs };

type EmailVerifyInputs = {
  headers: Bytes;
  signature: Bigint2048;
  publicKey: Bigint2048;
  modulusLength: number;
  bodyHashIndex: Field;
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

  // Extract components from DKIM result
  const headers = Bytes.from(dkimResult.headers);
  const signature = Bigint2048.from(dkimResult.signature);
  const publicKey = Bigint2048.from(dkimResult.publicKey);

  const modulusLength = dkimResult.modulusLength;

  // const headerBodyHash = Bytes.fromString(dkimResult.bodyHash);
  const bodyHashIndex = Field(
    dkimResult.headers.toString().indexOf(dkimResult.bodyHash) - 1
  );
  const body = Bytes.from(new Uint8Array(dkimResult.body));

  return { headers, signature, publicKey, modulusLength, bodyHashIndex, body };
}
