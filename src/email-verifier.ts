import { Field, Poseidon, Bytes, Hash } from 'o1js';

// Import the sha256 function from noble-hashes
//import { sha256 } from '@noble/hashes/sha256';
import { sha256 } from 'sha256-o1js/build/src/sha256.js'; 

import fs from "fs";
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const filePath = path.join(__dirname, '../../input.json'); 
//const rawEmail = fs.readFileSync(filePath, "utf8");
// Define interface to represent the structure of the JSON file
interface InputData {
    in_padded: string[];
    // Add other fields if necessary
  }
// Read the JSON file synchronously
const rawData: string = fs.readFileSync(filePath, 'utf-8');
// Parse the JSON data into the defined interface
const inputData: InputData = JSON.parse(rawData);
// Retrieve in_padded
const in_padded: string[] = inputData.in_padded;

console.log('in_padded: ', in_padded); 

const sha256Result = sha256(in_padded.join(''));

// // Display the result as an array of bytes
console.log('sha256Result: ', sha256Result);



// // test1: Create a Uint8Array from your 'in_padded' data (replace this with your actual data)
// const inputUint8Array = new TextEncoder().encode(in_padded.join(''));
// console.log('inputUint8Array: ',inputUint8Array); 
// console.log('type_of_inputUint8Array', typeof inputUint8Array); 




// // Now you can use in_padded in your TypeScript code
// //change bytes to string for sha256 repo testing purposes: 
// // Convert the array of bytes to a hexadecimal string for testing purposes: 
// const hexString: string = in_padded.map(byte => byte.toString().padStart(2, '0')).join('');
// // Use the hexString as input to the sha256 function
// //const result: Field[] = sha256(hexString);
// // Print the result
// console.log(hexString);

// // Convert the array of bytes to a binary string

// const binaryString = in_padded.map((byte: string) => parseInt(byte, 10).toString(2).padStart(8, '0')).join('');


// const paddingLength = 512 - (binaryString.length % 512) - 1;
// const paddedBinaryString = binaryString + '1' + '0'.repeat(Math.max(paddingLength, 0));

// // Convert the padded binary string back to an array of bytes
// const paddedBytes = [];
// for (let i = 0; i < paddedBinaryString.length; i += 8) {
//   paddedBytes.push(parseInt(paddedBinaryString.substr(i, 8), 2));
// }

// // Now, you can use the sha256 function with paddedBytes
// //const result = sha256(paddedBytes);

// // Print the result
// console.log(paddedBytes);

// // Call the sha256 function
// const sha256Result = sha256(paddedBytes);

// // // Display the result as an array of bytes
// console.log('sha256Result: ', sha256Result);






// interface EmailVerifierParams {
//     max_header_bytes: number;
//     max_body_bytes: number;
//     n: number;
//     k: number;
//     ignore_body_hash_check: boolean;
// }
  
// interface EmailVerifierSignals {
//     in_padded: Uint8Array;
//     pubkey: Uint8Array[];
//     signature: Uint8Array[];
//     in_len_padded_bytes: number;
// }

// function EmailVerifier(params: EmailVerifierParams, inputs: EmailVerifierSignals): void {
    
//     // Constraints; check 
//     if (params.max_header_bytes % 64 !== 0) {
//         throw new Error("max_header_bytes must be a multiple of 64");
//     }

//     if (params.max_body_bytes % 64 !== 0) {
//         throw new Error("max_body_bytes must be a multiple of 64");
//     }

//     if (params.n * params.k <= 2048) {
//         throw new Error("n * k must be greater than 2048");
//     }

//     if (params.n >= 255 / 2) {
//         throw new Error("n must be less than half of 255");
//     }

//     // Inputs 
//     const { in_padded, pubkey, signature, in_len_padded_bytes } = inputs;

    
//     // SHA of header 

//     sha256_output = sha256(in_padded,in_len_padded_bytes);  

//     // 
//     // VERIFY RSA SIGNATURE:




// // Example usage
// const emailVerifierParams: EmailVerifierParams = {
// max_header_bytes: 128,
// max_body_bytes: 256,
// n: 512,
// k: 2,
// ignore_body_hash_check: false,
// };

// const emailVerifierSignals: EmailVerifierSignals = {
// in_padded: new Uint8Array(128),
// pubkey: [new Uint8Array(512), new Uint8Array(512)],
// signature: [new Uint8Array(512), new Uint8Array(512)],
// in_len_padded_bytes: 256,
// };

// try {
// EmailVerifier(emailVerifierParams, emailVerifierSignals);
// console.log("Email verification successful!");
// } catch (error) {
// console.error("Email verification failed:", error.message);
// }





// // function poseidon(preimage: Field) {
// //   let hash = Poseidon.hash([preimage]);
// //   //hash.assertEquals(expectedHash);
// //   console.log(hash); 
// // }

// // poseidon(Field(0x0000000000000000000000000000000000000000000000000000000000000000n));

// // class Bytes16 extends Bytes(16) {} 
// // let bytes = Bytes16.from(new Array(16).fill(0));
// // //console.log(bytes); 

// // let bytes_hex = Bytes16.fromHex('646f67');
// // //console.log('bytes_hex', bytes_hex); 

// // let hani = Bytes16.fromString('dog');
// // //console.log('hani', hani)

// // //bytes.bytes.forEach((b) => console.log(b.toBigInt()));
// // bytes_hex.bytes.forEach((b) => console.log(b.toBigInt()));


// // define a preimage
// let preimage = 'The quick brown fox jumps over the lazy dog';

// // create a Bytes class that represents 43 bytes
// class Bytes43 extends Bytes(43) {}

// // convert the preimage to bytes
// let preimageBytes = Bytes43.fromString(preimage);

// // hash the preimage
// let hash = Hash.SHA3_256.hash(preimageBytes);

// console.log(hash.toHex());
// //69070dda01975c8c120c3aada1b282394e7f032fa9cf32f4cb2259a0897dfc04



// // const expectedHash =
// //   Field(0x28ce19420fc246a05553ad1e8c98f5c9d67166be2c18e9e4cb4b4e317dd2a78an);


// // import {
// //     Hash,
// //     Field,
// //     SmartContract,
// //     state,
// //     State,
// //     method,
// //     Permissions,
// //     Bytes,
// //   } from 'o1js';


// // export class EmailVerify extends SmartContract {
// //     @state(Field)  = State<Field>();

// //     @method rsa_verify (n, k) {

// //     }

// //     @method 

    
// //   }
