import {Bytes} from 'o1js'; 

export { 
    pkcs1v15Encode,
    canonicalizeBody
}

/**
* Still to do/check/address: 
* 1. since the digest in our case is 32ytes (sha256) maybe we can have emlen constant? its derived 
* from the publickey so check if it changes from 1024 to 2048 occasionally? or 4096?
* 2. length check is it necessary? 
* 3. The RFC gurantees 8 octets of '0xFF' paddings. Need to incorporate this. 
*/
function pkcs1v15Encode(
    digest: Bytes, 
    _emLen: number
) {
    // this represents the SHA256 algorithm as per the RFC3447 9.2 
    const digestAlgorithm = Bytes(19).fromHex('3031300d060960864801650304020105000420');
    // caculate length of padding needed. 
    const PSLength = _emLen - digestAlgorithm.length - digest.length - 3; 

    // Still not sure if this check is necessary. I see it in the Python implementation and also in
    // circom zkemail: https://github.com/zkemail/zk-email-verify/blob/fd7558af4ebf51be0bffb0f74437b0e7c996f5da/packages/circuits/helpers/rsa.circom#L110
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


// cancicalize as per the RFC for 
function canonicalizeBody(body: string){
    // convert to string
    // Step1: remove whitespaces 
    let  str = body.trimEnd();
    console.log('str', str); 
    // convert
    const trimmedBuffer = Buffer.from(str, 'utf-8');
    const canonicalizedBody = Buffer.concat([trimmedBuffer, Buffer.from("\r\n", 'utf-8')]);
    return canonicalizedBody; 
}

