import {
    Field,
    SmartContract,
    state,
    Bool,
    MerkleMap, 
    MerkleMapWitness,
    method,
    State
} from 'o1js';
  

export class DKIMRegistry extends SmartContract {
    // domainName => public key hash
    @state(Field) mapRoot = State<Field>(); 
    @state(Field) revokedRoot = State<Field>(); 
    // revoked public key hashes 
    //@state(Field) revokedDKIMPublicKeyHashes = State<Field>();

    // Do we need events? 
    // do we need the deploy function as per the https://github.com/o1-labs/docs2/blob/8c7476bde23e095ea02949f28f54dd3cf659e4f7/examples/zkapps/10-account-updates/src/SecondaryZkApp.ts#L14

    // Initialize the state
    init() {
        super.init();
        const merkleMap = new MerkleMap();
        this.mapRoot.set(merkleMap.getRoot());
        const revokedMap = new MerkleMap(); 
        this.revokedRoot.set(revokedMap.getRoot()); 
        //this.dkimPublicKeyHashes.set());
        //this.revokedDKIMPublicKeyHashes.set(Field(6));
    }

    @method async setDKIMPublicKeyHash(
        keyWitness: MerkleMapWitness,
        //revokedKeyWitness: MerkleMapWitness,
        domain: Field, 
        publicKeyHash: Field) {

        //get current roots; 
        const initialRoot = this.mapRoot.get(); 
        this.mapRoot.requireEquals(initialRoot); 

        // Check if the public key hash is not revoked
        const revokedRoot = this.revokedRoot.get(); 
        this.revokedRoot.requireEquals(revokedRoot); 
        // checkRoot = keyWitness.computeRootAndKey

        // update the merkle map with the new public key hash
        const [rootAfter, _ ] = keyWitness.computeRootAndKey(publicKeyHash); 
        this.mapRoot.set(rootAfter); 
    }

    
    @method async isDKIMPublicKeyHashValid(
        witness: MerkleMapWitness, 
        domain: Field, 
        publicKeyHash: Field, 
        ){
        const mapRoot = this.mapRoot.get(); 
        this.mapRoot.requireEquals(mapRoot); 
        const [computedRoot, key] = witness.computeRootAndKey(publicKeyHash); 
        this.mapRoot.requireEquals(computedRoot); 
        //check domain required matches the witness key
        key.assertEquals(domain); 
    }

    // @method async revokeDKIMPublicKeyHash(publicKeyHash: Field) {
    //}

}



