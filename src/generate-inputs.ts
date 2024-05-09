import fs from "fs";
import path from "path";
import { fileURLToPath } from 'url';
import { emailVerify } from "./email-verify.js";
import {Bytes} from 'o1js'; 
import { generateEmailVerifierInputs } from "@zk-email/helpers/dist/input-generators.js";
import { verifyDKIMSignature } from "@zk-email/helpers/dist/dkim/index.js"; 

// Read eml file input
const __dirname = path.dirname(fileURLToPath(import.meta.url));
// create eml folder in root and place en aml file you wish to verify there  
const filePath = path.join(__dirname, '../../eml/email.eml'); 
const rawEmail = fs.readFileSync(filePath, "utf8");



/// Helpers from zkemail 1. parsing 2. genertaing partial hash
/// o1js specific helper 
/// circuit inputs


// parse raw email 
//This method needs to be online to check public key of the domain specified in header
const dkimResult = await verifyDKIMSignature(Buffer.from(rawEmail));

const signature = dkimResult.signature; 
const publicKey = dkimResult.publicKey; 
const body = (dkimResult.body).toString('utf-8'); 
const bodyHash = dkimResult.bodyHash; 
const headers = Bytes.from(dkimResult.headers); 


// generate precomputed hash for body check 
const circuitInputs = await generateEmailVerifierInputs(rawEmail);
console.log('circuit inputs', circuitInputs);

let emailHeader = circuitInputs.emailHeader; 
let pubkey = circuitInputs.pubkey; 
let inputSignature = circuitInputs.signature; 
let emailBody = circuitInputs.emailBody; 

console.log('emailHeader', emailHeader);
console.log('pubkey', pubkey);
console.log('inputSignature', inputSignature);
console.log('emailBody', emailBody);
 


// // emailVerify

// headers: Bytes,
// signature: bigint,
// publicKey: bigint,
// bodyHashCheck: boolean,
// headerBodyHash:string, 
// body: string

emailVerify(headers,signature,publicKey,true,bodyHash,body); 






