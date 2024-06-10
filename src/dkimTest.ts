import { Contract } from 'ethers';
import { DKIMRegistry } from './DKIMRegistry.js';
import { Field, Mina, PrivateKey, AccountUpdate, MerkleMap } from 'o1js';

const useProof = false;

const Local = await Mina.LocalBlockchain({ proofsEnabled: useProof });
Mina.setActiveInstance(Local);

const deployerAccount = Local.testAccounts[0];
const deployerKey = deployerAccount.key;
const senderAccount = Local.testAccounts[1];
const senderKey = senderAccount.key;
// ----------------------------------------------------

// Create a public/private key pair. The public key is your address and where you deploy the zkApp to
const zkAppPrivateKey = PrivateKey.random();
const zkAppAddress = zkAppPrivateKey.toPublicKey();

// create an instance of DKIMRegistry - and deploy it to zkAppAddress
const zkAppInstance = new DKIMRegistry(zkAppAddress);
const deployTxn = await Mina.transaction(deployerAccount, async () => {
  AccountUpdate.fundNewAccount(deployerAccount);
  await zkAppInstance.deploy();
});
await deployTxn.sign([deployerKey, zkAppPrivateKey]).send();
console.log('DKIMRegistry deployed'); 

// get the initial state of Square after deployment
const initialState = zkAppInstance.mapRoot.get();
console.log('state after init:', initialState);

// prepare txn1 
const map = new MerkleMap; 
const rootBefore = map.getRoot(); 
const key = Field(100); 
const witness = map.getWitness(key); 

const txn1 = await Mina.transaction(deployerAccount, async () => {
  await zkAppInstance.setDKIMPublicKeyHash(
      witness, 
      key, 
      Field(5)
  );
});

await txn1.prove();
const pendingTx = txn1.sign([deployerKey]).send();
await pendingTx.wait(); 

// get the state after txn1
const afterState = zkAppInstance.mapRoot.get();
console.log('state after init:', afterState);

console.log('value for key: ', map.get(key)); 
