import fs from 'fs';
import { Bytes, UInt8 } from 'o1js';
import { Bigint2048 } from 'o1js-rsa';
import { emailVerify } from './email-verify.js';
import { EmailVerifyInputs, generateInputs } from './generate-inputs.js';

/**
 * Tests the email verification process using the provided inputs.
 *
 * @param inputs - The inputs required for the email verification.
 * @param ignoreBodyHashCheck - Flag to ignore the body hash check: default=true.
 * @param errorMessage - The expected error message if an error is expected.
 */
function testEmailVerify(
  inputs: EmailVerifyInputs,
  ignoreBodyHashCheck = true,
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

  // If an error message is provided, expect the emailVerify function to throw an error with the specified message
  if (errorMessage) {
    expect(callEmailVerify).toThrow(errorMessage);
  }
  // If no error message is provided, expect the emailVerify function to execute without throwing an error
  else {
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
    testEmailVerify(tamperedInputs, true, errorMessage);
    testEmailVerify(tamperedInputs, false, errorMessage);
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
    testEmailVerify(tamperedInputs, true, errorMessage);
    testEmailVerify(tamperedInputs, false, errorMessage);
  });

  //TODO Update RSA verification to throw meaningful error messages
  it('should fail if the DKIM signature is tampered with', async () => {
    // Use a random invalid DKIM signature
    const invalidSignature = Bigint2048.from(1234567n);
    const tamperedInputs = { ...inputs, signature: invalidSignature };

    const errorMessage =
      'Field.assertEquals(): 49157264413748767276814317779506976 != 42872445006125824354192737719310854';
    testEmailVerify(tamperedInputs, true, errorMessage);
    testEmailVerify(tamperedInputs, false, errorMessage);
  });

  it('should fail if the publicKey is tampered with', async () => {
    // Use a random invalid public key for DKIM signature verification
    const invalidPublicKey = Bigint2048.from(12345678910111213n);
    const tamperedInputs = { ...inputs, publicKey: invalidPublicKey };

    // An incorrect public key leads to RSA verification failure.
    const errorMessage =
      'Field.assertEquals(): 49157264413748767276814317779506976 != 7907045731297294';
    testEmailVerify(tamperedInputs, true, errorMessage);
    testEmailVerify(tamperedInputs, false, errorMessage);
  });

  it('should fail if the modulusLength is non-compliant', async () => {
    const incorrectModulusLength = 2048;
    const tamperedInputs = { ...inputs, modulusLength: incorrectModulusLength };

    // An incorrect modulus length results in non-compliant PKCS#1 v1.5 padding, affecting the hashed message integrity
    // leading to RSA signature verification failure.
    const errorMessage =
      'Field.assertEquals(): 83076749736557242056487941267521535 != 2417851639229258349412351';
    testEmailVerify(tamperedInputs, true, errorMessage);
    testEmailVerify(tamperedInputs, false, errorMessage);
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
    testEmailVerify(tamperedInputs, false, errorMessage);
  });

  //TODO Update bodyHash assertion to throw a meaningful error message
  it('should fail if the email bodyHashIndex is false', async () => {
    // Tamper with the bodyHash index
    const falseBodyHashIndex = inputs.bodyHashIndex.add(1);
    const tamperedInputs = { ...inputs, bodyHashIndex: falseBodyHashIndex };

    // Error message indicating a failed assertion for non-compliant bodyHash
    const errorMessage = 'Field.assertEquals(): 101 != 97';
    testEmailVerify(tamperedInputs, false, errorMessage);
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
    testEmailVerify(tamperedInputs, false, errorMessage);
  });
});
