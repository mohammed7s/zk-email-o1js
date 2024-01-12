import { generateCircuitInputs } from "@zk-email/helpers/dist/input-helpers.js";
import { verifyDKIMSignature } from "@zk-email/helpers/dist/dkim/index.js"; 
import { MAX_HEADER_PADDED_BYTES, MAX_BODY_PADDED_BYTES, STRING_PRESELECTOR } from "@zk-email/helpers/dist/constants.js";
import fs from "fs";
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const filePath = path.join(__dirname, '../../eml/Hello.eml'); 
const rawEmail = fs.readFileSync(filePath, "utf8");

//console.log(rawEmail);

const dkimResult = await verifyDKIMSignature(Buffer.from(rawEmail));

const signature = dkimResult.signature; 
const publicKey = dkimResult.publicKey; 
const body = dkimResult.body; 
const bodyHash = dkimResult.bodyHash; 
const message = dkimResult.message; 


// console.log('1', dkimResult); 
// console.log('2', signature); 
// console.log('3', publicKey); 
// console.log('4', body); 
// console.log('5', bodyHash);
// console.log('6', message); 


const circuitInputs = generateCircuitInputs({
  rsaSignature: dkimResult.signature, // The RSA signature of the email
  rsaPublicKey: dkimResult.publicKey, // The RSA public key used for verification
  body: dkimResult.body, // body of the email 
  bodyHash: dkimResult.bodyHash, // hash of the email body
  message: dkimResult.message, // the message that was signed (header + bodyHash)
  //Optional to verify regex in the body of email
  shaPrecomputeSelector: STRING_PRESELECTOR, // String to split the body for SHA pre computation 
  maxMessageLength: MAX_HEADER_PADDED_BYTES, // Maximum allowed length of the message in circuit
  maxBodyLength: MAX_BODY_PADDED_BYTES, // Maximum allowed length of the body in circuit
  ignoreBodyHashCheck : false, // To be used when ignore_body_hash_check is true in circuit
});

console.log(circuitInputs); 
// // // fs.writeFileSync("./input.json", JSON.stringify(circuitInputs));