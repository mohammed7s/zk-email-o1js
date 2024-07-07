import fs from 'fs';
import { Field, Bytes, UInt8 } from 'o1js';
import { Bigint2048 } from 'o1js-rsa';
import { emailVerify } from './email-verify.js';
import { EmailVerifyInputs, generateInputs } from './generate-inputs.js';

describe('emailVerify', () => {
  let inputs: EmailVerifyInputs;

  beforeAll(async () => {
    const rawEmail = fs.readFileSync('./eml/email-good.eml', 'utf8');
    inputs = await generateInputs(rawEmail);
  });

  it('should verify test email with no bodyHashCheck - correct body', async () => {
    // Call the provable emailVerify function
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
  });

  it('should verify test email with no bodyHashCheck - incorrect body', async () => {
    emailVerify(
      inputs.paddedHeader,
      inputs.headerHashIndex,
      inputs.signature,
      inputs.publicKey,
      inputs.modulusLength,
      false,
      Bytes(128).random(),
      inputs.precomputedHash,
      inputs.bodyHashIndex,
      inputs.headerBodyHashIndex
    );
  });

  it('should verify test email with bodyHashCheck', async () => {
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
  });

  it('should fail if the DKIM signature is wrong', async () => {
    // Use a random invalid DKIM signature
    const invalidSignature = Bigint2048.from(1234567n);
    expect(() => {
      emailVerify(
        inputs.paddedHeader,
        inputs.headerHashIndex,
        invalidSignature,
        inputs.publicKey,
        inputs.modulusLength,
        false,
        inputs.paddedBodyRemainingBytes,
        inputs.precomputedHash,
        inputs.bodyHashIndex,
        inputs.headerBodyHashIndex
      );
    }).toThrow();
  });

  it('should fail if DKIM message (headers) is tampered with', async () => {
    // Tamper with the headers bytes
    const tamperedHeadersBytes = Bytes.from([
      ...Bytes(64).random().bytes,
      ...inputs.paddedHeader.bytes,
    ]);
    expect(() => {
      emailVerify(
        tamperedHeadersBytes,
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
    }).toThrow();
  });

  it('should fail if the email body is tampered with', async () => {
    // Modify the last byte to tamper with the email body
    const tamperedBodyBytes = Bytes.from([
      ...inputs.paddedBodyRemainingBytes.bytes,
      UInt8.from(1),
    ]);
    expect(() => {
      emailVerify(
        inputs.paddedHeader,
        inputs.headerHashIndex,
        inputs.signature,
        inputs.publicKey,
        inputs.modulusLength,
        true, // Enable body hash check since we are tampering with the body
        tamperedBodyBytes,
        inputs.precomputedHash,
        inputs.bodyHashIndex,
        inputs.headerBodyHashIndex
      );
    }).toThrow();
  });

  it('should fail if the email bodyHashIndex is false', async function () {
    // Tamper with the body hash
    const falseBodyHashIndex = inputs.bodyHashIndex.add(Field.random());
    expect(() => {
      emailVerify(
        inputs.paddedHeader,
        inputs.headerHashIndex,
        inputs.signature,
        inputs.publicKey,
        inputs.modulusLength,
        true, // Enable body hash check since we are tampering with the body hash
        inputs.paddedBodyRemainingBytes,
        inputs.precomputedHash,
        falseBodyHashIndex,
        inputs.headerBodyHashIndex
      );
    }).toThrow();
  });
});
