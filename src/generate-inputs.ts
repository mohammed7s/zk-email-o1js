import { Field, Bytes } from 'o1js';
import { Bigint2048 } from 'o1js-rsa';
import { verifyDKIMSignature } from '@zk-email/helpers/dist/dkim/index.js';
import { dynamicSHA256Pad, generatePartialSHA256Inputs } from 'dynamic-sha256';

export { generateInputs, EmailVerifyInputs };

type EmailVerifyInputs = {
  paddedHeader: Bytes;
  headerHashIndex: Field;
  signature: Bigint2048;
  publicKey: Bigint2048;
  modulusLength: number;
  paddedBodyRemainingBytes: Bytes;
  precomputedHash: Bytes;
  bodyHashIndex: Field;
  headerBodyHashIndex: Field;
};

/**
 * Generates inputs required for email verification from a raw email string.
 *
 * @param rawEmail The raw email string.
 * @returns The email verification inputs.
 */
async function generateInputs(
  rawEmail: string,
  maxHeaderLength = 1024,
  maxRemainingBodyLength = 1536,
  shaPrecomputeSelector?: string
): Promise<EmailVerifyInputs> {
  // Parse raw email and retrieve public key of the domain in header
  const dkimResult = await verifyDKIMSignature(Buffer.from(rawEmail));

  const [paddedHeader, headerHashIndex] = dynamicSHA256Pad(
    dkimResult.headers,
    maxHeaderLength
  );

  const signature = Bigint2048.from(dkimResult.signature);
  const publicKey = Bigint2048.from(dkimResult.publicKey);

  const modulusLength = dkimResult.modulusLength;

  const {
    precomputedHash,
    messageRemainingBytes: paddedBodyRemainingBytes,
    digestIndex: bodyHashIndex,
  } = generatePartialSHA256Inputs(
    dkimResult.body,
    maxRemainingBodyLength,
    shaPrecomputeSelector
  );
  const headerBodyHashIndex = Field(
    dkimResult.headers.toString().indexOf(dkimResult.bodyHash) - 1
  );

  return {
    paddedHeader,
    headerHashIndex,
    signature,
    publicKey,
    modulusLength,
    paddedBodyRemainingBytes,
    precomputedHash,
    bodyHashIndex,
    headerBodyHashIndex,
  };
}
