import { Field, ZkProgram, Bytes } from 'o1js';
import { Bigint2048 } from 'o1js-rsa';
import { generateInputs } from './generate-inputs.js';
import { emailVerify } from './email-verify.js';
import fs from 'fs';

const filePath = './eml/email.eml';
const rawEmail = fs.readFileSync(filePath, 'utf8');

// TODO create generic ZKProgram function at runtime
const inputs = await generateInputs(rawEmail);
class HeadersBytes extends Bytes(inputs.headers.length) {}
class BodyBytes extends Bytes(inputs.body.length) {}

let verifyEmailZkProgram = ZkProgram({
  name: 'verify-email',
  methods: {
    verifyEmail: {
      privateInputs: [
        HeadersBytes.provable,
        Bigint2048,
        Bigint2048,
        Field,
        BodyBytes.provable,
      ],

      async method(
        headers: HeadersBytes,
        signature: Bigint2048,
        publicKey: Bigint2048,
        bodyHashIndex: Field,
        body: BodyBytes
      ) {
        emailVerify(
          headers,
          signature,
          publicKey,
          1024,
          true,
          bodyHashIndex,
          body
        );
      },
    },
  },
});

let { verifyEmail } = await verifyEmailZkProgram.analyzeMethods();

console.log(verifyEmail.summary());

console.time('compile');
await verifyEmailZkProgram.compile();
console.timeEnd('compile');

console.time('prove');

let proof = await verifyEmailZkProgram.verifyEmail(
  inputs.headers,
  inputs.signature,
  inputs.publicKey,
  inputs.bodyHashIndex,
  inputs.body
);
console.timeEnd('prove');

console.time('verify');
await verifyEmailZkProgram.verify(proof);
console.timeEnd('verify');
