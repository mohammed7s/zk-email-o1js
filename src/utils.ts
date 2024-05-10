import {Bytes} from 'o1js'; 

export { 
    pkcs1v15Encode,
    canonicalizeBody
}

/**
 * PKCS#1 v1.5 encoding.
 * This function follows the RFC3447 standard: https://datatracker.ietf.org/doc/html/rfc3447#section-9.2
 * Reference implementation: https://github.com/kmille/dkim-verify/blob/2efb21502d259a8738d9cec7e348c2fed95c3c7b/verify-dkim.py#L98
 * 
 * How it works:
 * - Takes a digest and pads it as follows: padding + hashing algorithm identifier + digest
 * - The target length of the encoded output is specified by emLen which is based on whether 1024, 2048, 5096
 * - The exact number of padding bytes of (0xFF) needed: emLen - algorithm identifier length - digest length - 3.
 * - Padding = '0001' + 0xFF bytes + '00'.
 * - Hashing algorithm identifier for SHA256 is '3031300d060960864801650304020105000420'.
 * 
 * Implementation Open Questions:
 * 1. Since the digest in our case is 32 bytes (sha256), maybe we can have emLen constant? It's derived 
 *    from the public key, so check if it changes from 1024 to 2048 occasionally? or 4096?
 * 2. Is length check necessary? 
 * 3. The RFC guarantees 8 octets of '0xFF' paddings. Need to incorporate this.
 * 
 * @param {Bytes} digest The digest to be encoded.
 * @param {number} emLen The length of the encoded output.
 * @returns {Bytes} The PKCS#1 v1.5 encoded digest.
 */
function pkcs1v15Encode(
    digest: Bytes, 
    _emLen: number
) {
    // SHA256 algorithm identifier 
    const digestAlgorithm = Bytes(19).fromHex('3031300d060960864801650304020105000420');
    // caculate length of padding needed. 
    const PSLength = _emLen - digestAlgorithm.length - digest.length - 3; 

    // Still not sure if this check is necessary. I see it in the Python implementation and also in the 
    // circom zkemail implementation: https://github.com/zkemail/zk-email-verify/blob/fd7558af4ebf51be0bffb0f74437b0e7c996f5da/packages/circuits/helpers/rsa.circom#L110
    // Given that we will have at minimum 1024bit RSA /128 bytes and always use sha256 (32bytes) for the hash. 
    if (_emLen < (digest.length + digestAlgorithm.length + 11)) {
        throw new Error(`Selected hash algorithm has a too long digest (${digest.length + digestAlgorithm.length} bytes).`);
    }
    // Check if this is acceptable to do in provable context. new Array? 
    const PS = new Array(PSLength).fill(0xFF);
    // create number of 0xFF bytes based on calculated PS length
    const PSBytes = Bytes(PSLength).from(PS); 

    // create padding with '0001' before the 'FF' sequence and then end with '00' 
    const pad1 = Bytes(2).fromHex('0001'); 
    const pad2 = Bytes(1).fromHex('00'); 
    // '0001' + PSBytes + '00' 
    let padding = pad1.bytes.concat(PSBytes.bytes).concat(pad2.bytes); 

    // digestInfo = digestAlgorithm + digest = '3031300d060960864801650304020105000420' + digest 
    let digestInfo = digestAlgorithm.bytes.concat(digest.bytes); 
    // final: '0001' + PSBytes + '00' + '3031300d060960864801650304020105000420' + digest
    let x = Bytes(_emLen).from(padding.concat(digestInfo)); 
    return x 
}


/**
 * Canonicalize the body as per RFC 6376 section 3.4.4 for "relaxed" Body Canonicalization Algorithm.
 * Reference implementation: https://github.com/kmille/dkim-verify/blob/2efb21502d259a8738d9cec7e348c2fed95c3c7b/verify-dkim.py#L17
 * 
 * @param {string} body The body to be canonicalized.
 * @returns {Buffer} The canonicalized body.
 */
function canonicalizeBody(body: string): Buffer {
    // Step 1: Remove trailing whitespaces and convert to string
    const str = body.trimEnd();
    // Step 2: Replace multiple consecutive spaces with a single space
    const normalizedStr = str.replace(/\s+/g, ' ');
    // Step 3: Ensure that line breaks use CRLF ("\r\n") and convert to UTF-8 encoded buffer
    const normalizedBuffer = Buffer.from(normalizedStr.replace(/\r?\n/g, '\r\n'), 'utf-8');
    // Step 4: Add CRLF sequence as per RFC
    const canonicalizedBody = Buffer.concat([normalizedBuffer, Buffer.from("\r\n", 'utf-8')]);

    return canonicalizedBody;
}



// // cancicalize as per the RFC 6376 section 3.4.4 for "relaxed" Body Canonicalization Algorithm 
// function canonicalizeBody(body: string){
//     // convert to string
//     // Step1: remove whitespaces 
//     let  str = body.trimEnd();
//     console.log('str', str); 
//     // convert
//     const trimmedBuffer = Buffer.from(str, 'utf-8');
//     const canonicalizedBody = Buffer.concat([trimmedBuffer, Buffer.from("\r\n", 'utf-8')]);
//     return canonicalizedBody; 
// }

