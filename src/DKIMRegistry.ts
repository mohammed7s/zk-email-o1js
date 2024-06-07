import {
    Field,
    SmartContract,
    state,
    Bool, 
    State
} from 'o1js';
  
export class DKIMRegistry extends SmartContract {
    // domainName => public key hash
    @state(Field) dkimPublicKeyHashes = State<Map<string, Field>>();
    // revoked public key hashes 
    @state(Field) revokedDKIMPublicKeyHashes = State<Map<Field, Bool>>();

    // Do we need events? 
    // do we need the deploy function as per the https://github.com/o1-labs/docs2/blob/8c7476bde23e095ea02949f28f54dd3cf659e4f7/examples/zkapps/10-account-updates/src/SecondaryZkApp.ts#L14

    // Initialize the state
    init() {
        super.init();
        this.dkimPublicKeyHashes.set(new Map());
        this.revokedDKIMPublicKeyHashes.set(new Map());
    }

    // @method async setDKIMPublicKeyHash(domainName: Field, publicKeyHash: Field) {
    // }

    // @method async revokeDKIMPublicKeyHash(publicKeyHash: Field) {
    // }

    // @method async isDKIMPublicKeyHashValid(domainName: Field, publicKeyHash: Field): Bool {
    // }
}



