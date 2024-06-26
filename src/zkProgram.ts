import { Field, ZkProgram, Bytes } from 'o1js';
import { Bigint2048 } from 'o1js-rsa';
import { generateInputs } from './generate-inputs.js';
import { emailVerify } from './email-verify.js';
import fs from 'fs';

const filePath = './eml/email.eml';
const rawEmail = fs.readFileSync(filePath, 'utf8');

const inputs = await generateInputs(rawEmail);

class HeadersBytes extends Bytes(1024) {}
class BodyBytes extends Bytes(1536) {}
class Bytes32 extends Bytes(32) {}

let verifyEmailZkProgram = ZkProgram({
  name: 'verify-email',
  methods: {
    verifyEmail: {
      privateInputs: [
        HeadersBytes.provable,
        Field,
        Bigint2048,
        Bigint2048,
        BodyBytes.provable,
        Bytes32.provable,
        Field,
        Field,
      ],

      async method(
        paddedHeader: Bytes,
        headerHashIndex: Field,
        signature: Bigint2048,
        publicKey: Bigint2048,
        paddedBodyRemainingBytes: Bytes,
        precomputedHash: Bytes,
        bodyHashIndex: Field,
        headerBodyHashIndex: Field
      ) {
        emailVerify(
          paddedHeader,
          headerHashIndex,
          signature,
          publicKey,
          1024,
          true,
          paddedBodyRemainingBytes,
          precomputedHash,
          bodyHashIndex,
          headerBodyHashIndex
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
  inputs.paddedHeader,
  inputs.headerHashIndex,
  inputs.signature,
  inputs.publicKey,
  inputs.paddedBodyRemainingBytes,
  inputs.precomputedHash,
  inputs.bodyHashIndex,
  inputs.headerBodyHashIndex
);
console.timeEnd('prove');

console.time('verify');
await verifyEmailZkProgram.verify(proof);
console.timeEnd('verify');
