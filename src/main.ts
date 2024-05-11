import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { generateInputs } from './generate-inputs.js';
import { emailVerify } from './email-verify.js';

// Read eml file input
const __dirname = path.dirname(fileURLToPath(import.meta.url));
// place a desired eml file in /eml folder and change name of file here
const filePath = path.join(__dirname, '../../eml/email.eml');
const rawEmail = fs.readFileSync(filePath, 'utf8');

async function main(rawEmail: string) {
  // offchain: generate circuit inputs
  const inputs = await generateInputs(rawEmail);
  // call the provable emailVerify function with parsed input
  emailVerify(
    inputs.headers,
    inputs.signature,
    inputs.publicKey,
    true,
    inputs.headerBodyHash,
    inputs.body
  );
}

main(rawEmail);
