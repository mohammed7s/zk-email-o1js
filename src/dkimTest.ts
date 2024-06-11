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

// initialize test merklMap
const map = new MerkleMap; 
const rootBefore = map.getRoot(); 
console.log("rootBefore ", rootBefore); 

// prepare txn1 
const domain = Field(100); 
const publicKeyHash = Field(50); 
map.set(domain, publicKeyHash); 

const rootAfter = map.getRoot(); 
console.log("rootAfter ", rootAfter); 

const witness = map.getWitness(domain); 
//console.log("witness ", witness); 


const txn1 = await Mina.transaction(deployerAccount, async () => {
  await zkAppInstance.setDKIMPublicKeyHash(
      witness, 
      domain, 
      publicKeyHash
  );
});

await txn1.prove();
const pendingTx = txn1.sign([deployerKey]).send();
await pendingTx.wait(); 

// get the state after txn1
const afterState = zkAppInstance.mapRoot.get();
console.log('state after tx1:', afterState);
console.log('value for key: ', map.get(domain)); 


// txn2: add another entry 
const rootBeforeTx2 = map.getRoot(); 
console.log("rootBeforetx2 ", rootBeforeTx2); 

const domain2 = Field(111);
const publicKeyHash2 = Field (222); 
const witness2 = map.getWitness(domain2); 
map.set(domain2, publicKeyHash2); 
const rootAfter2 = map.getRoot(); 
console.log("rootAfter2 ", rootAfter2); 

const txn2 = await Mina.transaction(deployerAccount, async () => {
  await zkAppInstance.setDKIMPublicKeyHash(
      witness2, 
      domain2, 
      publicKeyHash2
  );
});
await txn2.prove();
const pendingTx2 = txn2.sign([deployerKey]).send();
await pendingTx2.wait(); 

// get the state after txn2
const afterState2 = zkAppInstance.mapRoot.get();
console.log('state after tx2:', afterState2);
console.log('value for key: ', map.get(domain2)); 


//txn3: check if entry is valid for a valid entry 
const rootBeforeTx3 = map.getRoot(); 
console.log("rootBeforetx3 ", rootBeforeTx3); 
const txn3 = await Mina.transaction(deployerAccount, async () => {
  await zkAppInstance.isDKIMPublicKeyHashValid(
      witness2, 
      domain2, 
      publicKeyHash2
  );
});
await txn3.prove();
const pendingTx3 = txn3.sign([deployerKey]).send();
await pendingTx3.wait(); 
console.log("tnx3 completed: PublicKeyHash is valid"); 



//txn4: check if entry is not valid for a not valid entry  
const txn4 = await Mina.transaction(deployerAccount, async () => {
  await zkAppInstance.isDKIMPublicKeyHashValid(
      witness, 
      domain2, 
      publicKeyHash2
  );
});
await txn4.prove();
const pendingTx4 = txn3.sign([deployerKey]).send();
await pendingTx4.wait(); 
// should throw error 