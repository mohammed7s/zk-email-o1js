import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { generateInputs } from './generate-inputs.js';
import { emailVerify } from './email-verify.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
// Place a desired EML file in /eml folder and change the name of the file here
const filePath = path.join(__dirname, '../../eml/email.eml');
const rawEmail = fs.readFileSync(filePath, 'utf8');

/**
 * Reads an EML file input and verifies the email signature.
 *
 * @param rawEmail - The raw content of the EML file.
 */
async function main(rawEmail: string) {
  // Off-chain: generate circuit inputs
  const inputs = await generateInputs(rawEmail);
  // Call the provable emailVerify function with parsed input
  emailVerify(
    inputs.paddedHeader,
    inputs.headerHashIndex,
    inputs.signature,
    inputs.publicKey,
    inputs.modulusLength,
    false,
    inputs.paddedBodyRemainingBytes,
    inputs.precomputedHash,
    inputs.bodyHashIndex,
    inputs.headerBodyHashIndex
  );
}

main(rawEmail);
