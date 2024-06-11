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
    // revoked public key hashes 
    //@state(Field) revokedDKIMPublicKeyHashes = State<Field>();

    // Do we need events? 
    // do we need the deploy function as per the https://github.com/o1-labs/docs2/blob/8c7476bde23e095ea02949f28f54dd3cf659e4f7/examples/zkapps/10-account-updates/src/SecondaryZkApp.ts#L14

    // Initialize the state
    init() {
        super.init();
        const merkleMap = new MerkleMap();
        this.mapRoot.set(merkleMap.getRoot());
        //this.dkimPublicKeyHashes.set());
        //this.revokedDKIMPublicKeyHashes.set(Field(6));
    }

    @method async setDKIMPublicKeyHash(
        keyWitness: MerkleMapWitness,
        domain: Field, 
        publicKeyHash: Field) {

        //const key = domain; 
        const initialRoot = this.mapRoot.get(); 
        this.mapRoot.requireEquals(initialRoot); 

        const [rootAfter, _ ] = keyWitness.computeRootAndKey(publicKeyHash); 
        this.mapRoot.set(rootAfter); 

        //const key = stringToField(domain);
        //const merkleMap = new MerkleMap();
        
        // Load the current MerkleMap state from the smart contract state
        //const currentRoot = this.mapRoot.get();
    
        // // Ensure the public key hash is not revoked
        // const existingValue = merkleMap.get(key);
        // const isRevoked = existingValue.equals(Field(0)).not();
        // isRevoked.assertEquals(Bool(false), 'Cannot set a revoked public key');
    
        // Set the new value in the MerkleMap

        // merkleMap.set(key, publicKeyHash);
        // const newRoot = merkleMap.getRoot();
        // this.mapRoot.set(newRoot);
    }

    // @method async getDKIMPublicKeyHash(domain: Field): Field {
    //     const key = domain; 
    //     //const key = stringToField(domain);
    //     const merkleMap = new MerkleMap();
        
    //     // Load the current MerkleMap state from the smart contract state
    //     const currentRoot = this.mapRoot.get();
    //     merkleMap.loadFromRoot(currentRoot);
    
    //     return merkleMap.get(key);
    //   }
    //     // Ensure the public key hash is not revoked
    //     const isRevoked = this.revokedDKIMPublicKeyHashes.get().get(publicKeyHash) || Bool(false);
    //     isRevoked.assertEquals(Bool(false), 'cannot set revoked pubkey');
        
    //     // Check if already registered? 
    //     const HashExists = this.dkimPublicKeyHashes.get().get(domainName); 
    
    //     // Register the public key hash

    //     // this.dkimPublicKeyHashes.get().add(domainName, publicKeyHash);
    //     // const hashesForDomain = domainHashes.get(domainName) || new Set<Field>();
    //     // hashesForDomain.add(publicKeyHash);
    //     // domainHashes.set(domainName, hashesForDomain);
    
    // }

    // // @method async revokeDKIMPublicKeyHash(publicKeyHash: Field) {
    // // }

    // // @method async isDKIMPublicKeyHashValid(domainName: Field, publicKeyHash: Field): Bool {
    // // }
}



