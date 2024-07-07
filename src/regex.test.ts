import { Field, Bytes } from 'o1js';
import { bodyHashRegex, selectSubarray } from './utils';
import fs from 'fs';
import { verifyDKIMSignature } from '@zk-email/helpers/dist/dkim';

/**
 * Converts an array of UTF-8 encoded bytes (represented as bigints) into a string.
 *
 * This function handles single-byte (ASCII), two-byte, three-byte, and four-byte UTF-8 characters.
 * It processes the bytes, constructs the corresponding Unicode code points, and converts them into a string.
 *
 * @param bytes - An array of bigints representing UTF-8 encoded bytes.
 * @returns The decoded string from the UTF-8 bytes.
 */
function utf8BytesToString(bytes: bigint[]): string {
  let utf8String = '';
  let codepoint = 0;
  let remainingBytes = 0;

  for (const byte of bytes.map(Number)) {
    if (remainingBytes === 0) {
      if (byte <= 0x7f) {
        // Single byte character (ASCII)
        utf8String += String.fromCharCode(Number(byte));
      } else if (byte >= 0xc0 && byte <= 0xdf) {
        // Two byte character
        codepoint = byte & 0x1f;
        remainingBytes = 1;
      } else if (byte >= 0xe0 && byte <= 0xef) {
        // Three byte character
        codepoint = byte & 0x0f;
        remainingBytes = 2;
      } else if (byte >= 0xf0 && byte <= 0xf7) {
        // Four byte character
        codepoint = byte & 0x07;
        remainingBytes = 3;
      }
    } else {
      // Continuation byte
      codepoint = (codepoint << 6) | (byte & 0x3f);
      remainingBytes--;

      if (remainingBytes === 0) {
        utf8String += String.fromCharCode(codepoint);
      }
    }
  }

  return utf8String;
}

/**
 * Tests the `bodyHashRegex` function by verifying the count of matching patterns
 * and the revealed substring, if provided.
 *
 * @param input - The input string to be tested.
 * @param expectedCount - The expected count of matching patterns.
 * @param expectedSubstring - Optional. The expected substring to be revealed by the regex.
 */
function testBodyHashRegex(
  input: string,
  expectedCount: number,
  expectedSubstring?: string
) {
  const inputBytes = Bytes.fromString(input).bytes;
  const { out, reveal } = bodyHashRegex(inputBytes);

  if (expectedSubstring) {
    const revealedBytes = reveal[0]
      .map((f) => f.toBigInt())
      .filter((byte) => byte !== 0n);

    const revealedSubString = utf8BytesToString(revealedBytes);
    expect(revealedSubString).toEqual(expectedSubstring);
  }
  expect(out).toEqual(Field(expectedCount));
}

describe('Body Hash Regex Tests', () => {
  let emailString: string;
  beforeAll(async () => {
    emailString = fs.readFileSync('./eml/email-good.eml', 'utf8');
  });

  it('should reveal the correct body hash from an eml file', () => {
    testBodyHashRegex(
      emailString,
      1,
      'aeLbTnlUQQv2UFEWKHeiL5Q0NjOwj4ktNSInk8rN/P0='
    );
  });

  it('should reveal the correct body hash from a random string', () => {
    const input =
      'This is one example of email headers that contain\
    bh=7xQMDuoVVU4m0W0WRVSrVXMeGSIASsnucK9dJsrc+vU=;\
    that is acceped';

    testBodyHashRegex(input, 1, '7xQMDuoVVU4m0W0WRVSrVXMeGSIASsnucK9dJsrc+vU=');
  });

  it('should reject an input with two matching body hash patterns', () => {
    let input =
      emailString + 'bh=2JsdK4BMzzt9w4Zlz2TdyVCFc+l7vNyT5aAgGDYf7fM=;';
    expect(() => testBodyHashRegex(input, 1)).toThrow();
  });

  it('should reject input that does not match the body hash pattern - case 1', () => {
    const input = '=2JsdK4BMzzt9w4Zlz2TdyVCFc+l7vNyT5aAgGDYf7fM=;';
    expect(() => testBodyHashRegex(input, 1)).toThrow();
  });

  it('should reject input that does not match the body hash pattern - case 2', () => {
    const input = '2JsdK4BMzzt9w4Zlz2TdyVCFc+l7vNyT5aAgGDYf7fM=;';
    expect(() => testBodyHashRegex(input, 1)).toThrow();
  });

  it('should reject input that does not match the body hash pattern - case 3', () => {
    const input = 'b=2JsdK4BMzzt9w4Zlz2TdyVCFc+l7vNyT5aAgGDYf7fM=;';
    expect(() => testBodyHashRegex(input, 1)).toThrow();
  });

  it('should reject input that does not match the body hash pattern - case 4', () => {
    const input = 'h=2JsdK4BMzzt9w4Zlz2TdyVCFc+l7vNyT5aAgGDYf7fM=;';
    expect(() => testBodyHashRegex(input, 1)).toThrow();
  });

  it('should reject input that does not match the body hash pattern - case 5', () => {
    const input = 'bh=2JsdK4BMzzt9w4Zlz2TdyVCFc+l7vNyT5aAgGDYf7fM=';
    expect(() => testBodyHashRegex(input, 1)).toThrow();
  });

  it('should reject input with non Base64 body hash', () => {
    const input = 'bh=2JsdK4BMz#zt9w4Zlz2TdyVCFc+l7vNyT5aAgGDYf7fM=';
    expect(() => testBodyHashRegex(input, 1)).toThrow();
  });

  it('should select the correct revealed body hash bytes from an eml file', async () => {
    const { headers, bodyHash } = await verifyDKIMSignature(
      Buffer.from(emailString)
    );

    const { out, reveal } = bodyHashRegex(Bytes.from(headers).bytes);
    expect(out).toEqual(Field(1));

    const bodyHashIndex = headers.toString().indexOf(bodyHash) - 1;
    const selectedBodyHashBytes = selectSubarray(
      reveal[0],
      Field(bodyHashIndex),
      44
    );

    const revealedBodyHash = utf8BytesToString(
      selectedBodyHashBytes.map((x) => x.toBigInt())
    );
    expect(revealedBodyHash).toEqual(
      'aeLbTnlUQQv2UFEWKHeiL5Q0NjOwj4ktNSInk8rN/P0='
    );
  });
});
