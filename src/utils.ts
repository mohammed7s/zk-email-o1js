import { Field, Bool, UInt8, Bytes, assert, Provable } from 'o1js';
import { Bigint2048 } from 'o1js-rsa';

export { pkcs1v15Pad, bodyHashRegex, selectSubarray };

/**
 * Creates a PKCS#1 v1.5 padded message for the given SHA-256 digest.
 *
 * @note This function follows the RFC3447 standard: https://datatracker.ietf.org/doc/html/rfc3447#section-9.2
 *
 * @param sha256Digest The SHA-256 digest to be padded.
 * @param modulusLength The size of the RSA modulus in bytes.
 * @returns The padded PKCS#1 v1.5 message.
 */
function pkcs1v15Pad(sha256Digest: Bytes, modulusLength: number) {
  // Algorithm identifier (OID) for SHA-256 in PKCS#1 v1.5 padding
  const algorithmConstantBytes = Bytes.fromHex(
    '3031300d060960864801650304020105000420'
  ).bytes;

  // Calculate the length of the padding string (PS)
  const padLength =
    modulusLength - sha256Digest.length - algorithmConstantBytes.length - 3;

  // Create the padding string (PS) with 0xFF bytes based on padLength
  const paddingString = Bytes.from(new Array(padLength).fill(0xff));

  // Assemble the PKCS#1 v1.5 padding components
  const padding = [
    ...Bytes.fromHex('0001').bytes, // Block type (BT) 00 01
    ...paddingString.bytes, // Padding string (PS)
    ...Bytes.fromHex('00').bytes, // Separator byte 00
    ...algorithmConstantBytes, // Algorithm identifier (OID)
    ...sha256Digest.bytes, // SHA-256 digest
  ];

  // Convert the padded message to a byte array
  const paddedHash = Bytes.from(padding);

  // Create a Bigint2048 witness from the padded hash
  const message = Provable.witness(Bigint2048, () => {
    const hexString = '0x' + paddedHash.toHex();
    return Bigint2048.from(BigInt(hexString));
  });

  return message;
}

/**
 * Scans the input ASCII bytes for a matching body hash pattern.
 *
 * @note This function is compiled using the o1js zk-regex compiler: https://github.com/Shigoto-dev19/zk-regex-o1js
 *       The regex pattern used is `bh=([a-zA-Z0-9]|\\+|/|=)+;`, revealing only base64 characters `([a-zA-Z0-9]|\\+|/|=)+` with `countEnabled` set to true.
 *
 * @param input The input array of UInt8 bytes to be scanned.
 * @returns An object containing:
 *          - `out`: A Field representing the matching count (1 or more if found, 0 otherwise).
 *          - `reveal`: An array of Field arrays, revealing the base64 characters upon pattern match.
 */
function bodyHashRegex(input: UInt8[]) {
  const num_bytes = input.length;
  let states: Bool[][] = Array.from({ length: num_bytes + 1 }, () => []);
  let state_changed: Bool[] = Array.from({ length: num_bytes }, () =>
    Bool(false)
  );

  states[0][0] = Bool(true);
  for (let i = 1; i < 6; i++) {
    states[0][i] = Bool(false);
  }

  for (let i = 0; i < num_bytes; i++) {
    const lt0 = new UInt8(65).lessThanOrEqual(input[i]);
    const lt1 = input[i].lessThanOrEqual(90);
    const and0 = lt0.and(lt1);
    const lt2 = new UInt8(97).lessThanOrEqual(input[i]);
    const lt3 = input[i].lessThanOrEqual(122);
    const and1 = lt2.and(lt3);
    const eq0 = input[i].value.equals(43);
    const eq1 = input[i].value.equals(47);
    const eq2 = input[i].value.equals(48);
    const eq3 = input[i].value.equals(49);
    const eq4 = input[i].value.equals(50);
    const eq5 = input[i].value.equals(51);
    const eq6 = input[i].value.equals(52);
    const eq7 = input[i].value.equals(53);
    const eq8 = input[i].value.equals(54);
    const eq9 = input[i].value.equals(55);
    const eq10 = input[i].value.equals(56);
    const eq11 = input[i].value.equals(57);
    const eq12 = input[i].value.equals(61);
    let multi_or0 = Bool(false);
    multi_or0 = multi_or0.or(and0);
    multi_or0 = multi_or0.or(and1);
    multi_or0 = multi_or0.or(eq0);
    multi_or0 = multi_or0.or(eq1);
    multi_or0 = multi_or0.or(eq2);
    multi_or0 = multi_or0.or(eq3);
    multi_or0 = multi_or0.or(eq4);
    multi_or0 = multi_or0.or(eq5);
    multi_or0 = multi_or0.or(eq6);
    multi_or0 = multi_or0.or(eq7);
    multi_or0 = multi_or0.or(eq8);
    multi_or0 = multi_or0.or(eq9);
    multi_or0 = multi_or0.or(eq10);
    multi_or0 = multi_or0.or(eq11);
    multi_or0 = multi_or0.or(eq12);
    const and2 = states[i][1].and(multi_or0);
    const and3 = states[i][5].and(multi_or0);
    let multi_or1 = Bool(false);
    multi_or1 = multi_or1.or(and2);
    multi_or1 = multi_or1.or(and3);
    states[i + 1][1] = multi_or1;
    state_changed[i] = state_changed[i].or(states[i + 1][1]);
    const eq13 = input[i].value.equals(98);
    const and4 = states[i][0].and(eq13);
    states[i + 1][2] = and4;
    state_changed[i] = state_changed[i].or(states[i + 1][2]);
    const eq14 = input[i].value.equals(104);
    const and5 = states[i][2].and(eq14);
    states[i + 1][3] = and5;
    state_changed[i] = state_changed[i].or(states[i + 1][3]);
    const eq15 = input[i].value.equals(59);
    const and6 = states[i][1].and(eq15);
    states[i + 1][4] = and6;
    state_changed[i] = state_changed[i].or(states[i + 1][4]);
    const and7 = states[i][3].and(eq12);
    states[i + 1][5] = and7;
    state_changed[i] = state_changed[i].or(states[i + 1][5]);
    states[i + 1][0] = state_changed[i].not();
  }

  let final_state_sum: Field[] = [];
  final_state_sum[0] = states[0][4].toField();
  for (let i = 1; i <= num_bytes; i++) {
    final_state_sum[i] = final_state_sum[i - 1].add(states[i][4].toField());
  }
  const out = final_state_sum[num_bytes];

  const msg_bytes = num_bytes - 1;
  const is_consecutive: Bool[][] = Array.from({ length: num_bytes }, () => []);
  is_consecutive[msg_bytes][1] = Bool(true);
  for (let i = 0; i < msg_bytes; i++) {
    is_consecutive[msg_bytes - 1 - i][0] = states[num_bytes - i][4]
      .and(is_consecutive[msg_bytes - i][1].not())
      .or(is_consecutive[msg_bytes - i][1]);
    is_consecutive[msg_bytes - 1 - i][1] = state_changed[msg_bytes - i].and(
      is_consecutive[msg_bytes - 1 - i][0]
    );
  }

  // revealed transitions: [[[5,1],[1,1]]]
  let reveal: Field[][] = [];

  // the 0-th substring transitions: [[5,1],[1,1]]
  const is_reveal0: Bool[] = [];
  let is_substr0: Bool[][] = Array.from({ length: msg_bytes }, () => []);
  const reveal0: Field[] = [];
  for (let i = 0; i < msg_bytes - 1; i++) {
    is_substr0[i][0] = Bool(false);
    is_substr0[i][1] = is_substr0[i][0].or(
      states[i + 1][5].and(states[i + 2][1])
    );
    is_substr0[i][2] = is_substr0[i][1].or(
      states[i + 1][1].and(states[i + 2][1])
    );
    is_reveal0[i] = is_substr0[i][2].and(is_consecutive[i][1]);
    reveal0[i] = input[i + 1].value.mul(is_reveal0[i].toField());
  }
  reveal.push(reveal0);

  return { out, reveal };
}

/**
 * Provably select a subarray from an array of field elements.
 *
 * @notice The length of the output array can be reduced by setting `subarrayLength`.
 * @notice Based on https://demo.hedgedoc.org/s/Le0R3xUhB.
 * @notice Assumes field elements to be bytes in the input array.
 *
 * @param input - The input array of field elements.
 * @param startIndex - The starting index for the subarray selection.
 * @param subarrayLength - The length of the output subarray.
 *
 * @returns The selected subarray of bytes.
 * @throws Will throw an error if `subarrayLength` is greater than the input array length.
 */
function selectSubarray(
  input: Field[],
  startIndex: Field,
  subarrayLength: number
): UInt8[] {
  const maxArrayLen = input.length;
  assert(
    subarrayLength <= maxArrayLen,
    'Subarray length exceeds input array length!'
  );

  // Assert startIndex is not zero
  startIndex.assertNotEquals(
    0,
    'Subarray start index must be greater than zero!'
  );

  const bitLength = Math.ceil(Math.log2(maxArrayLen));
  const shiftBits = startIndex.toBits(bitLength);
  let tmp: Field[][] = Array.from({ length: bitLength }, () =>
    Array.from({ length: maxArrayLen }, () => Field(0))
  );

  for (let j = 0; j < bitLength; j++) {
    for (let i = 0; i < maxArrayLen; i++) {
      let offset = (i + (1 << j)) % maxArrayLen;
      // Shift left by 2^j indices if bit is 1
      if (j === 0) {
        tmp[j][i] = shiftBits[j]
          .toField()
          .mul(input[offset].sub(input[i]))
          .add(input[i]);
      } else {
        tmp[j][i] = shiftBits[j]
          .toField()
          .mul(tmp[j - 1][offset].sub(tmp[j - 1][i]))
          .add(tmp[j - 1][i]);
      }
    }
  }

  // Return last row
  let subarray: UInt8[] = [];
  for (let i = 0; i < subarrayLength; i++) {
    const selectedByte = UInt8.Unsafe.fromField(tmp[bitLength - 1][i]);

    // In the context of zk-regex, matched data consists of non-null bytes, while unmatched data consists of null bytes
    // Assert that the subarray data doesn't contain a 0 (null) byte
    selectedByte.value.assertNotEquals(
      0,
      'Selected subarray bytes should not contain null bytes!'
    );

    subarray.push(selectedByte);
  }

  return subarray;
}
