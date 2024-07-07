import {
  Field,
  Mina,
  Bytes,
  SmartContract,
  method,
  state,
  State,
  Poseidon,
  PrivateKey,
  AccountUpdate,
  UInt8,
  Bool,
} from 'o1js';
import { Bigint2048 } from 'o1js-rsa';
import { generateInputs } from './generate-inputs.js';
import { emailVerify } from './email-verify.js';
import fs from 'fs';

const filePath = './eml/twitter.eml';
const rawEmail = fs.readFileSync(filePath, 'utf8');
const inputs = await generateInputs(rawEmail);

const computedHashPrint = Poseidon.hash(inputs.publicKey.fields);
console.log(computedHashPrint);

class HeadersBytes extends Bytes(1024) {}
class BodyBytes extends Bytes(1536) {}

class Twitter extends SmartContract {
  @state(Field) TwitterPublicKeyHash = State<Field>();

  init() {
    super.init();
    // Use the hash you computed earlier
    const computedHash = Poseidon.hash(inputs.publicKey.fields);
    this.TwitterPublicKeyHash.set(computedHash);
  }

  @method async verify_handle(
    paddedHeader: HeadersBytes,
    headerHashIndex: Field,
    signature: Bigint2048,
    publicKey: Bigint2048,
    paddedBodyRemainingBytes: BodyBytes,
    precomputedHash: Bytes,
    bodyHashIndex: Field,
    headerBodyHashIndex: Field
  ) {
    // check public key has matches the stored:
    const currentTwitterPublicKeyHash = await this.TwitterPublicKeyHash.get();
    this.TwitterPublicKeyHash.requireEquals(this.TwitterPublicKeyHash.get());
    const publickeyhash = Poseidon.hash(publicKey.fields);
    publickeyhash.assertEquals(currentTwitterPublicKeyHash);

    // email verify email signature with body hash check
    emailVerify(
      paddedHeader,
      headerHashIndex,
      signature,
      publicKey,
      1024,
      false,
      paddedBodyRemainingBytes,
      precomputedHash,
      bodyHashIndex,
      headerBodyHashIndex
    );

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    let { out, reveal } = twitterInputRegex(paddedHeader.bytes);
    out.assertEquals(true, 'regex check fail. not a valid email');
  }

  // @method async updateTwitterPublicKeyHash () { }
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
    inputs.paddedHeader,
    inputs.headerHashIndex,
    inputs.signature,
    inputs.publicKey,
    inputs.paddedBodyRemainingBytes,
    inputs.precomputedHash,
    inputs.bodyHashIndex,
    inputs.headerBodyHashIndex
  );
});

await txn1.prove();
const pendingTx = txn1.sign([deployerKey]).send();
await pendingTx.wait();

// regex fuction ran with this commandL: npm run zk-regex 'password resets for @[A-Za-z0-9]+' '[A-Za-z0-9]+'

// npm run zk-regex 'This email was meant for @[A-Za-z0-9_]+' '["[A-Za-z0-9_]+"]'
function twitterInputRegex(input: UInt8[]) {
  const num_bytes = input.length;
  let states: Bool[][] = Array.from({ length: num_bytes + 1 }, () => []);
  let state_changed: Bool[] = Array.from({ length: num_bytes }, () =>
    Bool(false)
  );

  states[0][0] = Bool(true);
  for (let i = 1; i < 28; i++) {
    states[0][i] = Bool(false);
  }

  for (let i = 0; i < num_bytes; i++) {
    const eq0 = input[i].value.equals(64);
    const and0 = states[i][27].and(eq0);
    states[i + 1][1] = and0;
    state_changed[i] = state_changed[i].or(states[i + 1][1]);
    const lt0 = new UInt8(65).lessThanOrEqual(input[i]);
    const lt1 = input[i].lessThanOrEqual(90);
    const and1 = lt0.and(lt1);
    const lt2 = new UInt8(97).lessThanOrEqual(input[i]);
    const lt3 = input[i].lessThanOrEqual(122);
    const and2 = lt2.and(lt3);
    const eq1 = input[i].value.equals(48);
    const eq2 = input[i].value.equals(49);
    const eq3 = input[i].value.equals(50);
    const eq4 = input[i].value.equals(51);
    const eq5 = input[i].value.equals(52);
    const eq6 = input[i].value.equals(53);
    const eq7 = input[i].value.equals(54);
    const eq8 = input[i].value.equals(55);
    const eq9 = input[i].value.equals(56);
    const eq10 = input[i].value.equals(57);
    const eq11 = input[i].value.equals(95);
    let multi_or0 = Bool(false);
    multi_or0 = multi_or0.or(and1);
    multi_or0 = multi_or0.or(and2);
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
    const and3 = states[i][1].and(multi_or0);
    const and4 = states[i][2].and(multi_or0);
    let multi_or1 = Bool(false);
    multi_or1 = multi_or1.or(and3);
    multi_or1 = multi_or1.or(and4);
    states[i + 1][2] = multi_or1;
    state_changed[i] = state_changed[i].or(states[i + 1][2]);
    const eq12 = input[i].value.equals(84);
    const and5 = states[i][0].and(eq12);
    states[i + 1][3] = and5;
    state_changed[i] = state_changed[i].or(states[i + 1][3]);
    const eq13 = input[i].value.equals(104);
    const and6 = states[i][3].and(eq13);
    states[i + 1][4] = and6;
    state_changed[i] = state_changed[i].or(states[i + 1][4]);
    const eq14 = input[i].value.equals(105);
    const and7 = states[i][4].and(eq14);
    states[i + 1][5] = and7;
    state_changed[i] = state_changed[i].or(states[i + 1][5]);
    const eq15 = input[i].value.equals(115);
    const and8 = states[i][5].and(eq15);
    states[i + 1][6] = and8;
    state_changed[i] = state_changed[i].or(states[i + 1][6]);
    const eq16 = input[i].value.equals(32);
    const and9 = states[i][6].and(eq16);
    states[i + 1][7] = and9;
    state_changed[i] = state_changed[i].or(states[i + 1][7]);
    const eq17 = input[i].value.equals(101);
    const and10 = states[i][7].and(eq17);
    states[i + 1][8] = and10;
    state_changed[i] = state_changed[i].or(states[i + 1][8]);
    const eq18 = input[i].value.equals(109);
    const and11 = states[i][8].and(eq18);
    states[i + 1][9] = and11;
    state_changed[i] = state_changed[i].or(states[i + 1][9]);
    const eq19 = input[i].value.equals(97);
    const and12 = states[i][9].and(eq19);
    states[i + 1][10] = and12;
    state_changed[i] = state_changed[i].or(states[i + 1][10]);
    const and13 = states[i][10].and(eq14);
    states[i + 1][11] = and13;
    state_changed[i] = state_changed[i].or(states[i + 1][11]);
    const eq20 = input[i].value.equals(108);
    const and14 = states[i][11].and(eq20);
    states[i + 1][12] = and14;
    state_changed[i] = state_changed[i].or(states[i + 1][12]);
    const and15 = states[i][12].and(eq16);
    states[i + 1][13] = and15;
    state_changed[i] = state_changed[i].or(states[i + 1][13]);
    const eq21 = input[i].value.equals(119);
    const and16 = states[i][13].and(eq21);
    states[i + 1][14] = and16;
    state_changed[i] = state_changed[i].or(states[i + 1][14]);
    const and17 = states[i][14].and(eq19);
    states[i + 1][15] = and17;
    state_changed[i] = state_changed[i].or(states[i + 1][15]);
    const and18 = states[i][15].and(eq15);
    states[i + 1][16] = and18;
    state_changed[i] = state_changed[i].or(states[i + 1][16]);
    const and19 = states[i][16].and(eq16);
    states[i + 1][17] = and19;
    state_changed[i] = state_changed[i].or(states[i + 1][17]);
    const and20 = states[i][17].and(eq18);
    states[i + 1][18] = and20;
    state_changed[i] = state_changed[i].or(states[i + 1][18]);
    const and21 = states[i][18].and(eq17);
    states[i + 1][19] = and21;
    state_changed[i] = state_changed[i].or(states[i + 1][19]);
    const and22 = states[i][19].and(eq19);
    states[i + 1][20] = and22;
    state_changed[i] = state_changed[i].or(states[i + 1][20]);
    const eq22 = input[i].value.equals(110);
    const and23 = states[i][20].and(eq22);
    states[i + 1][21] = and23;
    state_changed[i] = state_changed[i].or(states[i + 1][21]);
    const eq23 = input[i].value.equals(116);
    const and24 = states[i][21].and(eq23);
    states[i + 1][22] = and24;
    state_changed[i] = state_changed[i].or(states[i + 1][22]);
    const and25 = states[i][22].and(eq16);
    states[i + 1][23] = and25;
    state_changed[i] = state_changed[i].or(states[i + 1][23]);
    const eq24 = input[i].value.equals(102);
    const and26 = states[i][23].and(eq24);
    states[i + 1][24] = and26;
    state_changed[i] = state_changed[i].or(states[i + 1][24]);
    const eq25 = input[i].value.equals(111);
    const and27 = states[i][24].and(eq25);
    states[i + 1][25] = and27;
    state_changed[i] = state_changed[i].or(states[i + 1][25]);
    const eq26 = input[i].value.equals(114);
    const and28 = states[i][25].and(eq26);
    states[i + 1][26] = and28;
    state_changed[i] = state_changed[i].or(states[i + 1][26]);
    const and29 = states[i][26].and(eq16);
    states[i + 1][27] = and29;
    state_changed[i] = state_changed[i].or(states[i + 1][27]);
    states[i + 1][0] = state_changed[i].not();
  }

  let final_state_result = Bool(false);
  for (let i = 0; i <= num_bytes; i++) {
    final_state_result = final_state_result.or(states[i][2]);
  }
  const out = final_state_result;

  const msg_bytes = num_bytes - 1;
  const is_consecutive: Bool[][] = Array.from({ length: num_bytes }, () => []);
  is_consecutive[msg_bytes][1] = Bool(true);
  for (let i = 0; i < msg_bytes; i++) {
    is_consecutive[msg_bytes - 1 - i][0] = states[num_bytes - i][2]
      .and(is_consecutive[msg_bytes - i][1].not())
      .or(is_consecutive[msg_bytes - i][1]);
    is_consecutive[msg_bytes - 1 - i][1] = state_changed[msg_bytes - i].and(
      is_consecutive[msg_bytes - 1 - i][0]
    );
  }

  // revealed transitions: [[[1,2],[2,2]]]
  let reveal: Field[][] = [];

  // the 0-th substring transitions: [[1,2],[2,2]]
  const is_reveal0: Bool[] = [];
  let is_substr0: Bool[][] = Array.from({ length: msg_bytes }, () => []);
  const reveal0: Field[] = [];
  for (let i = 0; i < msg_bytes; i++) {
    is_substr0[i][0] = Bool(false);
    is_substr0[i][1] = is_substr0[i][0].or(
      states[i + 1][1].and(states[i + 2][2])
    );
    is_substr0[i][2] = is_substr0[i][1].or(
      states[i + 1][2].and(states[i + 2][2])
    );
    is_reveal0[i] = is_substr0[i][2].and(is_consecutive[i][1]);
    reveal0[i] = input[i + 1].value.mul(is_reveal0[i].toField());
  }
  reveal.push(reveal0);

  return { out, reveal };
}
