import { Field, Mina, Bytes, SmartContract, method, state, State, Hash, PrivateKey, AccountUpdate, UInt8, Bool} from 'o1js';
import { Bigint2048 } from 'o1js-rsa';
import { generateInputs } from './generate-inputs.js';
import { emailVerify } from './email-verify.js';
import fs from 'fs';

const filePath = './eml/twitter.eml';
const rawEmail = fs.readFileSync(filePath, 'utf8');
const inputs = await generateInputs(rawEmail);

const computedHashPrint = Hash.Poseidon.hash(inputs.publicKey.fields);
console.log(computedHashPrint); 

class HeadersBytes extends Bytes(inputs.headers.length) {}
class BodyBytes extends Bytes(inputs.body.length) {}

class Twitter extends SmartContract {
  @state(Field) TwitterPublicKeyHash = State<Field>();

  init() {
    super.init();
    // Use the hash you computed earlier
    const computedHash = Hash.Poseidon.hash(inputs.publicKey.fields);
    this.TwitterPublicKeyHash.set(computedHash);
  }

  @method async verify_handle(
    headers: HeadersBytes,
    signature: Bigint2048,
    publicKey: Bigint2048,
    bodyHashIndex: Field,
    body: BodyBytes
  ) {
    // check public key has matches the stored: 
    const currentTwitterPublicKeyHash = await this.TwitterPublicKeyHash.get();
    this.TwitterPublicKeyHash.requireEquals(this.TwitterPublicKeyHash.get());
    const publickeyhash = Hash.Poseidon.hash(publicKey.fields); 
    publickeyhash.assertEquals(currentTwitterPublicKeyHash);

    // email verify email signature with body hash check
    emailVerify(
      headers,
      signature,
      publicKey,
      2048,
      true,
      bodyHashIndex,
      body
    );

    // // check regex 
    // let { out, reveal } = twitterInputRegex(body.bytes);
    // out.assertEquals(true, "regex check fail. not a valid email");

  } 

  // @method async updateTwitterPublicKeyHash () {

  // }


}




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
const zkAppInstance = new Twitter(zkAppAddress);
const deployTxn = await Mina.transaction(deployerAccount, async () => {
  AccountUpdate.fundNewAccount(deployerAccount);
  await zkAppInstance.deploy();
});
await deployTxn.sign([deployerKey, zkAppPrivateKey]).send();
console.log('DKIMRegistry deployed'); 

// get the initial state of Square after deployment
const initialState = zkAppInstance.TwitterPublicKeyHash.get();
console.log('state after init:', initialState);


const txn1 = await Mina.transaction(deployerAccount, async () => {
  await zkAppInstance.verify_handle(
      inputs.headers,
      inputs.signature, 
      inputs.publicKey,
      inputs.bodyHashIndex,
      inputs.body
  );
});

await txn1.prove();
const pendingTx = txn1.sign([deployerKey]).send();
await pendingTx.wait(); 




// regex fuction ran with this commandL: npm run zk-regex 'password resets for @[A-Za-z0-9]+' '[A-Za-z0-9]+'

function twitterInputRegex(input: UInt8[]) {
  const num_bytes = input.length;
  let states: Bool[][] = Array.from({ length: num_bytes + 1 }, () => []);
  let state_changed: Bool[] = Array.from({ length: num_bytes }, () => Bool(false));

  states[0][0] = Bool(true);
  for (let i = 1; i < 22; i++) {
          states[0][i] = Bool(false);
  }

  for (let i = 0; i < num_bytes; i++) {
          const eq0 = input[i].value.equals(9);
          const eq1 = input[i].value.equals(10);
          const eq2 = input[i].value.equals(11);
          const eq3 = input[i].value.equals(12);
          const eq4 = input[i].value.equals(13);
          let multi_or0 = Bool(false);
          multi_or0 = multi_or0.or(eq0);
          multi_or0 = multi_or0.or(eq1);
          multi_or0 = multi_or0.or(eq2);
          multi_or0 = multi_or0.or(eq3);
          multi_or0 = multi_or0.or(eq4);
          const and0 = states[i][1].and(multi_or0);
          const and1 = states[i][21].and(multi_or0);
          let multi_or1 = Bool(false);
          multi_or1 = multi_or1.or(and0);
          multi_or1 = multi_or1.or(and1);
          states[i+1][1] = multi_or1;
          state_changed[i] = state_changed[i].or(states[i+1][1]);
          const eq5 = input[i].value.equals(102);
          const and2 = states[i][1].and(eq5);
          states[i+1][2] = and2;
          state_changed[i] = state_changed[i].or(states[i+1][2]);
          const eq6 = input[i].value.equals(111);
          const and3 = states[i][2].and(eq6);
          states[i+1][3] = and3;
          state_changed[i] = state_changed[i].or(states[i+1][3]);
          const eq7 = input[i].value.equals(114);
          const and4 = states[i][3].and(eq7);
          states[i+1][4] = and4;
          state_changed[i] = state_changed[i].or(states[i+1][4]);
          const and5 = states[i][4].and(multi_or0);
          const and6 = states[i][5].and(multi_or0);
          let multi_or2 = Bool(false);
          multi_or2 = multi_or2.or(and5);
          multi_or2 = multi_or2.or(and6);
          states[i+1][5] = multi_or2;
          state_changed[i] = state_changed[i].or(states[i+1][5]);
          const eq8 = input[i].value.equals(64);
          const and7 = states[i][5].and(eq8);
          states[i+1][6] = and7;
          state_changed[i] = state_changed[i].or(states[i+1][6]);
          const eq9 = input[i].value.equals(83);
          const and8 = states[i][6].and(eq9);
          const and9 = states[i][7].and(eq9);
          let multi_or3 = Bool(false);
          multi_or3 = multi_or3.or(and8);
          multi_or3 = multi_or3.or(and9);
          states[i+1][7] = multi_or3;
          state_changed[i] = state_changed[i].or(states[i+1][7]);
          const eq10 = input[i].value.equals(112);
          const and10 = states[i][0].and(eq10);
          states[i+1][8] = and10;
          state_changed[i] = state_changed[i].or(states[i+1][8]);
          const eq11 = input[i].value.equals(97);
          const and11 = states[i][8].and(eq11);
          states[i+1][9] = and11;
          state_changed[i] = state_changed[i].or(states[i+1][9]);
          const eq12 = input[i].value.equals(115);
          const and12 = states[i][9].and(eq12);
          states[i+1][10] = and12;
          state_changed[i] = state_changed[i].or(states[i+1][10]);
          const and13 = states[i][10].and(eq12);
          states[i+1][11] = and13;
          state_changed[i] = state_changed[i].or(states[i+1][11]);
          const eq13 = input[i].value.equals(119);
          const and14 = states[i][11].and(eq13);
          states[i+1][12] = and14;
          state_changed[i] = state_changed[i].or(states[i+1][12]);
          const and15 = states[i][12].and(eq6);
          states[i+1][13] = and15;
          state_changed[i] = state_changed[i].or(states[i+1][13]);
          const and16 = states[i][13].and(eq7);
          states[i+1][14] = and16;
          state_changed[i] = state_changed[i].or(states[i+1][14]);
          const eq14 = input[i].value.equals(100);
          const and17 = states[i][14].and(eq14);
          states[i+1][15] = and17;
          state_changed[i] = state_changed[i].or(states[i+1][15]);
          const and18 = states[i][15].and(multi_or0);
          const and19 = states[i][16].and(multi_or0);
          let multi_or4 = Bool(false);
          multi_or4 = multi_or4.or(and18);
          multi_or4 = multi_or4.or(and19);
          states[i+1][16] = multi_or4;
          state_changed[i] = state_changed[i].or(states[i+1][16]);
          const and20 = states[i][16].and(eq7);
          states[i+1][17] = and20;
          state_changed[i] = state_changed[i].or(states[i+1][17]);
          const eq15 = input[i].value.equals(101);
          const and21 = states[i][17].and(eq15);
          states[i+1][18] = and21;
          state_changed[i] = state_changed[i].or(states[i+1][18]);
          const and22 = states[i][18].and(eq12);
          states[i+1][19] = and22;
          state_changed[i] = state_changed[i].or(states[i+1][19]);
          const and23 = states[i][19].and(eq15);
          states[i+1][20] = and23;
          state_changed[i] = state_changed[i].or(states[i+1][20]);
          const eq16 = input[i].value.equals(116);
          const and24 = states[i][20].and(eq16);
          states[i+1][21] = and24;
          state_changed[i] = state_changed[i].or(states[i+1][21]);
          states[i+1][0] = state_changed[i].not();
  }

  let final_state_result = Bool(false);
  for (let i = 0; i <= num_bytes; i++) {
          final_state_result = final_state_result.or(states[i][7]);
  }
  const out = final_state_result;

  const msg_bytes = num_bytes - 1;
  const is_consecutive: Bool[][] = Array.from({ length: num_bytes }, () => []);
  is_consecutive[msg_bytes][1] = Bool(true);
  for (let i = 0; i < msg_bytes; i++) {
          is_consecutive[msg_bytes-1-i][0] = states[num_bytes-i][7].and(is_consecutive[msg_bytes-i][1].not()).or(is_consecutive[msg_bytes-i][1]);
          is_consecutive[msg_bytes-1-i][1] = state_changed[msg_bytes-i].and(is_consecutive[msg_bytes-1-i][0]);
  }

  // revealed transitions: [[[6,7],[7,7]]]
  let reveal: Field[][] = [];

  // the 0-th substring transitions: [[6,7],[7,7]]
  const is_reveal0: Bool[] = [];
  let is_substr0: Bool[][] = Array.from({ length: msg_bytes }, () => []);
  const reveal0: Field[] = [];
  for (let i = 0; i < msg_bytes; i++) {
          is_substr0[i][0] = Bool(false);
          is_substr0[i][1] = is_substr0[i][0].or(states[i+1][6].and(states[i+2][7]));
          is_substr0[i][2] = is_substr0[i][1].or(states[i+1][7].and(states[i+2][7]));
          is_reveal0[i] = is_substr0[i][2].and(is_consecutive[i][1]);
          reveal0[i] = input[i+1].value.mul(is_reveal0[i].toField());
  }
  reveal.push(reveal0);

  return { out, reveal };
}






