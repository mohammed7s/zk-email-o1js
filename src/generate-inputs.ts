import { Bytes } from 'o1js';
//import {Bigint2048} from 'o1js-rsa';
//import { generateEmailVerifierInputs } from "@zk-email/helpers/dist/input-generators.js";
import { verifyDKIMSignature } from '@zk-email/helpers/dist/dkim/index.js';

export { generateInputs };

type EmailVerifyInputs = {
  headers: Bytes;
  signature: bigint;
  publicKey: bigint;
  headerBodyHash: string;
  body: string;
};

async function generateInputs(rawEmail: string): Promise<EmailVerifyInputs> {
  // parse raw email and retrieves public key of the domain in header
  const dkimResult = await verifyDKIMSignature(Buffer.from(rawEmail));
  console.log('publicKey', dkimResult.publicKey.toString(2).length);
  const headers = Bytes.from(dkimResult.headers);
  const signature = BigInt(dkimResult.signature);
  const publicKey = BigInt(dkimResult.publicKey);
  const headerBodyHash = dkimResult.bodyHash.toString();
  const body = dkimResult.body.toString('utf-8');
  return { headers, signature, publicKey, headerBodyHash, body };
}

// // generate precomputed hash for body check
// const circuitInputs = await generateEmailVerifierInputs(rawEmail);
// console.log('circuit inputs', circuitInputs);

// let emailHeader = circuitInputs.emailHeader;
// let pubkey = circuitInputs.pubkey;
// let inputSignature = circuitInputs.signature;
// let emailBody = circuitInputs.emailBody;

// console.log('emailHeader', emailHeader);
// console.log('pubkey', pubkey);
// console.log('inputSignature', inputSignature);
// console.log('emailBody', emailBody);

// emailVerify(headers, signature, publicKey, true, bodyHash, body);
