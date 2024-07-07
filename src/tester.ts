/**
 * This script is a utility for testing email verification on an EML file.
 * You can quickly run this script to verify the integrity and authenticity of the email's DKIM signature.
 *
 * Usage:
 * 1. Place the desired EML file in the `eml` directory or any other directory of your choice.
 * 2. Update the `filePath` variable to point to your new EML file.
 * 3. Execute the script by running the `npm run tester` command.
 *
 * Note:
 * - If no output is produced, it means the verification was successful.
 * - If an error is thrown, it indicates a problem with the verification process.
 *
 * This script is primarily for debugging purposes and experimenting with different EML files using the emailVerify provable function.
 *
 * Additionally, this script has highlighted some limitations in helper functions,
 * such as support issues for certain email providers like Hotmail and ProtonMail.
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { generateInputs } from './generate-inputs.js';
import { emailVerify } from './email-verify.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
// Update this variable to point to your desired EML file
const filePath = path.join(__dirname, '../../eml/email-good-large.eml');
const rawEmail = fs.readFileSync(filePath, 'utf8');

/**
 * Reads an EML file input and verifies the email signature.
 *
 * @param rawEmail - The raw content of the EML file.
 */
async function verifyEmail(rawEmail: string) {
  // Off-chain: generate circuit inputs
  const inputs = await generateInputs(rawEmail);
  // Call the provable emailVerify function with parsed inputs
  emailVerify(
    inputs.paddedHeader,
    inputs.headerHashIndex,
    inputs.signature,
    inputs.publicKey,
    inputs.modulusLength,
    true,
    inputs.paddedBodyRemainingBytes,
    inputs.precomputedHash,
    inputs.bodyHashIndex,
    inputs.headerBodyHashIndex
  );
}

// Execute the verification process
verifyEmail(rawEmail);
