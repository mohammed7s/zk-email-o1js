import fs from 'fs';
import { Bytes, Field, UInt8 } from 'o1js';
import { Bigint2048 } from 'o1js-rsa';
import { emailVerify } from './email-verify.js';
import { EmailVerifyInputs, generateInputs } from './generate-inputs.js';

/**
 * Tests the email verification process using the provided inputs.
 *
 * @param inputs - The inputs required for the email verification.
 * @param ignoreBodyHashCheck - Flag to ignore the body hash check: default=true.
 * @param shouldThrow - Flag to indicate if the function should throw an error: default=false.
 * @param errorMessage - The expected error message if an error is expected.
 */
function testEmailVerify(
  inputs: EmailVerifyInputs,
  ignoreBodyHashCheck = true,
  shouldThrow = false,
  errorMessage?: string
) {
  // Function to call the emailVerify function with the provided inputs
  const callEmailVerify = () =>
    emailVerify(
      inputs.paddedHeader,
      inputs.headerHashIndex,
      inputs.signature,
      inputs.publicKey,
      inputs.modulusLength,
      !ignoreBodyHashCheck,
      inputs.paddedBodyRemainingBytes,
      inputs.precomputedHash,
      inputs.bodyHashIndex,
      inputs.headerBodyHashIndex
    );

  if (shouldThrow) {
    if (errorMessage) {
      // Expect the emailVerify function to throw an error with the specified message
      expect(callEmailVerify).toThrow(errorMessage);
    } else {
      // Expect the emailVerify function to throw an error without a specific message
      expect(callEmailVerify).toThrow();
    }
  } else {
    // Expect the emailVerify function to execute without throwing an error
    expect(callEmailVerify).not.toThrow();
  }
}

describe('emailVerify: email-good', () => {
  let inputs: EmailVerifyInputs;

  beforeAll(async () => {
    const rawEmail = fs.readFileSync('./eml/email-good.eml', 'utf8');
    inputs = await generateInputs(rawEmail);
  });

  it('should verify test email with bodyHashCheck disabled - correct body', async () => {
    testEmailVerify(inputs);
  });

  it('should verify test email with bodyHashCheck disabled - incorrect body', async () => {
    const tamperedBodyBytes = Bytes(128).random();
    const tamperedInputs = {
      ...inputs,
      paddedBodyRemainingBytes: tamperedBodyBytes,
    };

    testEmailVerify(tamperedInputs, true);
  });

  it('should verify test email with bodyHashCheck enabled', async () => {
    testEmailVerify(inputs, false);
  });

  it('should fail if the DKIM message (headers) is tampered with', async () => {
    const tamperedHeaderBytes = Bytes.from([
      ...Bytes(64).random().bytes,
      ...inputs.paddedHeader.bytes,
    ]);
    const tamperedInputs = { ...inputs, paddedHeader: tamperedHeaderBytes };

    // Error message stemming from dynamic SHA256 padding
    const errorMessage = 'Padding error at index 161: expected zero.';
    testEmailVerify(tamperedInputs, true, true, errorMessage);
    testEmailVerify(tamperedInputs, false, true, errorMessage);
  });

  it('should fail if the headerHashIndex is tampered with', async () => {
    const tamperedHeaderHashIndex = inputs.headerHashIndex.add(1);
    const tamperedInputs = {
      ...inputs,
      headerHashIndex: tamperedHeaderHashIndex,
    };

    // If headerHashIndex is incorrect, the computed message hash will be incorrect,
    // leading to the failure of RSA signature verification.
    const errorMessage =
      'Field.assertEquals(): 47747604729107447858111623096549830 != 49157264413748767276814317779506976';
    testEmailVerify(tamperedInputs, true, true, errorMessage);
    testEmailVerify(tamperedInputs, false, true, errorMessage);
  });

  //TODO Update RSA verification to throw meaningful error messages
  it('should fail if the DKIM signature is tampered with', async () => {
    // Use a random invalid DKIM signature
    const invalidSignature = Bigint2048.from(1234567n);
    const tamperedInputs = { ...inputs, signature: invalidSignature };

    const errorMessage =
      'Field.assertEquals(): 49157264413748767276814317779506976 != 42872445006125824354192737719310854';
    testEmailVerify(tamperedInputs, true, true, errorMessage);
    testEmailVerify(tamperedInputs, false, true, errorMessage);
  });

  it('should fail if the publicKey is tampered with', async () => {
    // Use a random invalid public key for DKIM signature verification
    const invalidPublicKey = Bigint2048.from(12345678910111213n);
    const tamperedInputs = { ...inputs, publicKey: invalidPublicKey };

    // An incorrect public key leads to RSA verification failure.
    const errorMessage =
      'Field.assertEquals(): 49157264413748767276814317779506976 != 7907045731297294';
    testEmailVerify(tamperedInputs, true, true, errorMessage);
    testEmailVerify(tamperedInputs, false, true, errorMessage);
  });

  it('should fail if the modulusLength is non-compliant', async () => {
    // The correct modulus length is 1024
    const incorrectModulusLength = 2048;
    const tamperedInputs = { ...inputs, modulusLength: incorrectModulusLength };

    // An incorrect modulus length results in non-compliant PKCS#1 v1.5 padding, affecting the hashed message integrity
    // leading to RSA signature verification failure.
    const errorMessage =
      'Field.assertEquals(): 83076749736557242056487941267521535 != 2417851639229258349412351';
    testEmailVerify(tamperedInputs, true, true, errorMessage);
    testEmailVerify(tamperedInputs, false, true, errorMessage);
  });

  it('should fail if the email body is tampered with', async () => {
    // Modify the last byte to tamper with the email body
    const tamperedBodyBytes = Bytes.from([
      ...inputs.paddedBodyRemainingBytes.bytes,
      UInt8.from(1),
    ]);
    const tamperedInputs = {
      ...inputs,
      paddedBodyRemainingBytes: tamperedBodyBytes,
    };

    // Error message stemming from dynamic SHA256 padding
    const errorMessage = 'Array length must be a multiple of 16';
    testEmailVerify(tamperedInputs, false, true, errorMessage);
  });

  it('should fail if the precomputed Hash is non-compliant', async () => {
    // Expect the initial precomputed hash to match the initial SHA256 hash value, as no selector was used during input generation
    const expectedHash =
      '6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19';
    expect(inputs.precomputedHash.toHex()).toEqual(expectedHash);

    // Tamper with the precomputed hash
    const tamperedPrecomputedHash = Bytes.from(
      Array.from({ length: 32 }, (_, i) => i + 1)
    );
    const tamperedInputs = {
      ...inputs,
      precomputedHash: tamperedPrecomputedHash,
    };

    // An incorrect precomputed hash will cause the body hash integrity check to fail
    const errorMessage = 'Field.assertEquals(): 115 != 97';
    testEmailVerify(tamperedInputs, false, true, errorMessage);
  });

  //TODO Update bodyHash assertion to throw a meaningful error message
  it('should fail if the email bodyHashIndex is false', async () => {
    // Tamper with the bodyHash index
    const falseBodyHashIndex = inputs.bodyHashIndex.add(1);
    const tamperedInputs = { ...inputs, bodyHashIndex: falseBodyHashIndex };

    // Error message indicating a failed assertion for non-compliant bodyHash
    const errorMessage = 'Field.assertEquals(): 101 != 97';
    testEmailVerify(tamperedInputs, false, true, errorMessage);
  });

  it('should fail if the email headerBodyHashIndex is false', async () => {
    // headerBodyHashIndex marks the starting index of the body hash within the header bytes
    const falseHeaderBodyHashIndex = inputs.headerBodyHashIndex.add(1);
    const tamperedInputs = {
      ...inputs,
      headerBodyHashIndex: falseHeaderBodyHashIndex,
    };

    // Error message indicating that the body hash fetched with zk-regex does not match the expected body hash index in the headers
    const errorMessage =
      'Selected subarray bytes should not contain null bytes!';
    testEmailVerify(tamperedInputs, false, true, errorMessage);
  });
});

describe('emailVerify: email-good-large', () => {
  let inputs: EmailVerifyInputs;

  beforeAll(async () => {
    const rawEmail = fs.readFileSync('./eml/email-good-large.eml', 'utf8');
    inputs = await generateInputs(rawEmail, 1024, 1536, 'thousands');
  });

  it('should verify test email with bodyHashCheck disabled - correct body', async () => {
    testEmailVerify(inputs);
  });

  it('should verify test email with bodyHashCheck disabled - incorrect body', async () => {
    const tamperedBodyBytes = Bytes(128).random();
    const tamperedInputs = {
      ...inputs,
      paddedBodyRemainingBytes: tamperedBodyBytes,
    };

    testEmailVerify(tamperedInputs, true);
  });

  it('should verify test email with bodyHashCheck enabled', async () => {
    testEmailVerify(inputs, false);
  });

  it('should fail if the DKIM message (headers) is tampered with', async () => {
    const tamperedHeaderBytes = Bytes.from([
      ...Bytes(64).random().bytes,
      ...inputs.paddedHeader.bytes,
    ]);
    const tamperedInputs = { ...inputs, paddedHeader: tamperedHeaderBytes };

    testEmailVerify(tamperedInputs, true, true);
    testEmailVerify(tamperedInputs, false, true);
  });

  it('should fail if the headerHashIndex is tampered with', async () => {
    const tamperedHeaderHashIndex = inputs.headerHashIndex.add(1);
    const tamperedInputs = {
      ...inputs,
      headerHashIndex: tamperedHeaderHashIndex,
    };

    testEmailVerify(tamperedInputs, true, true);
    testEmailVerify(tamperedInputs, false, true);
  });

  it('should fail if the DKIM signature is tampered with', async () => {
    // Use a random invalid DKIM signature
    const invalidSignature = Bigint2048.from(1234567n);
    const tamperedInputs = { ...inputs, signature: invalidSignature };

    testEmailVerify(tamperedInputs, true, true);
    testEmailVerify(tamperedInputs, false, true);
  });

  it('should fail if the publicKey is tampered with', async () => {
    // Use a random invalid public key for DKIM signature verification
    const invalidPublicKey = Bigint2048.from(Field.random().toBigInt());
    const tamperedInputs = { ...inputs, publicKey: invalidPublicKey };

    testEmailVerify(tamperedInputs, true, true);
    testEmailVerify(tamperedInputs, false, true);
  });

  it('should fail if the modulusLength is non-compliant', async () => {
    // The correct modulus length is 2048
    const incorrectModulusLength = 1024;
    const tamperedInputs = { ...inputs, modulusLength: incorrectModulusLength };

    testEmailVerify(tamperedInputs, true, true);
    testEmailVerify(tamperedInputs, false, true);
  });

  it('should fail if the email body is tampered with', async () => {
    // Add a randomly generated 64-byte block
    const tamperedBodyBytes = Bytes.from([
      ...inputs.paddedBodyRemainingBytes.bytes,
      ...Bytes(64).random().bytes,
    ]);
    const tamperedInputs = {
      ...inputs,
      paddedBodyRemainingBytes: tamperedBodyBytes,
    };

    testEmailVerify(tamperedInputs, false, true);
  });

  it('should fail if the precomputed Hash is non-compliant', async () => {
    // Expect the initial precomputed hash to not match the initial SHA256 hash value, as a string selector was used during input generation
    const expectedHash =
      '6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19';
    expect(inputs.precomputedHash.toHex()).not.toEqual(expectedHash);

    // Tamper with the precomputed hash
    const tamperedPrecomputedHash = Bytes(32).random();
    const tamperedInputs = {
      ...inputs,
      precomputedHash: tamperedPrecomputedHash,
    };

    testEmailVerify(tamperedInputs, false, true);
  });

  it('should fail if the email bodyHashIndex is false', async () => {
    // Tamper with the bodyHash index
    const falseBodyHashIndex = inputs.bodyHashIndex.add(1);
    const tamperedInputs = { ...inputs, bodyHashIndex: falseBodyHashIndex };

    testEmailVerify(tamperedInputs, false, true);
  });

  it('should fail if the email headerBodyHashIndex is false', async () => {
    const falseHeaderBodyHashIndex = inputs.headerBodyHashIndex.add(1);
    const tamperedInputs = {
      ...inputs,
      headerBodyHashIndex: falseHeaderBodyHashIndex,
    };

    testEmailVerify(tamperedInputs, false, true);
  });
});
