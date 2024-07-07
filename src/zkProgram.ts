//! Note: Compiling and generating proofs for the existing `emailVerify` circuits is not possible
//! because the total number of rows far exceeds the 2^16 constraint limit of o1js circuits.

import { Field, ZkProgram, Bytes } from 'o1js';
import { Bigint2048 } from 'o1js-rsa';
import { emailVerify } from './email-verify.js';

class Bytes32 extends Bytes(32) {}

class HeadersBytes extends Bytes(1024) {}
class BodyBytes1536 extends Bytes(1536) {}
class BodyBytes1024 extends Bytes(1024) {}

let verifyEmailZkProgram = ZkProgram({
  name: 'verify-email',
  methods: {
    verifyEmailNoBodyCheck: {
      privateInputs: [
        HeadersBytes.provable,
        Field,
        Bigint2048,
        Bigint2048,
        BodyBytes1536.provable,
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
          false,
          paddedBodyRemainingBytes,
          precomputedHash,
          bodyHashIndex,
          headerBodyHashIndex
        );
      },
    },

    verifyEmailBodyCheck1024: {
      privateInputs: [
        HeadersBytes.provable,
        Field,
        Bigint2048,
        Bigint2048,
        BodyBytes1024.provable,
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

    verifyEmailBodyCheck1536: {
      privateInputs: [
        HeadersBytes.provable,
        Field,
        Bigint2048,
        Bigint2048,
        BodyBytes1536.provable,
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

const {
  verifyEmailNoBodyCheck,
  verifyEmailBodyCheck1536,
  verifyEmailBodyCheck1024,
} = await verifyEmailZkProgram.analyzeMethods();

console.log(
  'verifyEmailNoBodyCheck summary: ',
  verifyEmailNoBodyCheck.summary()
);

console.log(
  '\nverifyEmailBodyCheck1024 summary: ',
  verifyEmailBodyCheck1024.summary()
);

console.log(
  '\nverifyEmailBodyCheck1536 summary: ',
  verifyEmailBodyCheck1536.summary()
);
