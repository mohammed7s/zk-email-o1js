import fs from 'fs';
import { Field, Bytes, UInt8 } from 'o1js';
import { Bigint2048 } from 'o1js-rsa';
import { emailVerify } from './email-verify.js';
import { EmailVerifyInputs, generateInputs } from './generate-inputs.js';

describe('emailVerify', () => {
  let inputs: EmailVerifyInputs;

  beforeAll(async () => {
    const rawEmail = fs.readFileSync('./eml/email.eml', 'utf8');
    inputs = await generateInputs(rawEmail);
  });

  // The RSA parameters are imported from the example email in this repo: https://github.com/kmille/dkim-verify/tree/master
  it('should verify hardcoded valid DKIM parameters', async () => {
    const params = {
      message:
        '746f3a6d6f68616d6d6564303837373440676d61696c2e636f6d0d0a6d6573736167652d69643a3c42413730464230352d343531362d343846442d394638412d41343930443338393134433740676d61696c2e636f6d3e0d0a7375626a6563743a48656c6c6f0d0a646174653a5468752c2032312044656320323032332031343a35333a3332202b303533300d0a6d696d652d76657273696f6e3a312e302028312e30290d0a66726f6d3a6d6f68616d6d656420687573617269203c6d6f68616d6d656468757361726940676d61696c2e636f6d3e0d0a636f6e74656e742d7472616e736665722d656e636f64696e673a376269740d0a646b696d2d7369676e61747572653a763d313b20613d7273612d7368613235363b20633d72656c617865642f72656c617865643b20643d676d61696c2e636f6d3b20733d32303233303630313b20743d313730333135303632393b20783d313730333735353432393b20646172613d676f6f676c652e636f6d3b20683d746f3a6d6573736167652d69643a7375626a6563743a646174653a6d696d652d76657273696f6e3a66726f6d203a636f6e74656e742d7472616e736665722d656e636f64696e673a66726f6d3a746f3a63633a7375626a6563743a646174653a6d6573736167652d6964203a7265706c792d746f3b2062683d4a696b41416a77625143665158724d67494738767a782b68327446543653574364792f65457870525a62303d3b20623d',
      signature:
        '2937796533901000631008854690689140641270226768693786607772896083893378946198108395533513438785931181798949124505915916109223757535944407901047721805096487266307792245430443194307947639434612588085781825229002286673745779070563204991707204844050939882163781262572749550555771513235078888507301365306081030333361037728494215829049511898397148405652194469566353863123327386150506155825977956549404312556305012389030914149069897348906894159660752716454814471522831326603879677365029521905685579250953496810863071682733671861385584088939470669122929866494770741725638060444921898329222224442107461676015715071909766986049',
      publicKey:
        '20054049931062868895890884170436368122145070743595938421415808271536128118589158095389269883866014690926251520949836343482211446965168263353397278625494421205505467588876376305465260221818103647257858226961376710643349248303872103127777544119851941320649869060657585270523355729363214754986381410240666592048188131951162530964876952500210032559004364102337827202989395200573305906145708107347940692172630683838117810759589085094521858867092874903269345174914871903592244831151967447426692922405241398232069182007622735165026000699140578092635934951967194944536539675594791745699200646238889064236642593556016708235359',
    };

    const message = Bytes.fromHex(params.message);
    const signature = Bigint2048.from(BigInt(params.signature));
    const publicKey = Bigint2048.from(BigInt(params.publicKey));

    emailVerify(
      message,
      signature,
      publicKey,
      2048,
      false,
      Field(0),
      Bytes.from([0])
    );
  });

  it('should verify test email with no bodyHashCheck - correct body', async () => {
    // Call the provable emailVerify function
    emailVerify(
      inputs.headers,
      inputs.signature,
      inputs.publicKey,
      inputs.modulusLength,
      false,
      inputs.bodyHashIndex,
      inputs.body
    );
  });

  it('should verify test email with no bodyHashCheck - incorrect body', async () => {
    emailVerify(
      inputs.headers,
      inputs.signature,
      inputs.publicKey,
      inputs.modulusLength,
      false,
      inputs.bodyHashIndex,
      Bytes.from([...inputs.body.bytes, UInt8.from(0)])
    );
  });

  it('should verify test email with bodyHashCheck', async () => {
    emailVerify(
      inputs.headers,
      inputs.signature,
      inputs.publicKey,
      inputs.modulusLength,
      true,
      inputs.bodyHashIndex,
      inputs.body
    );
  });

  it('should fail if the DKIM signature is wrong', async () => {
    // Use a random invalid DKIM signature
    const invalidSignature = Bigint2048.from(1234567n);
    expect(() => {
      emailVerify(
        inputs.headers,
        invalidSignature,
        inputs.publicKey,
        inputs.modulusLength,
        false,
        inputs.bodyHashIndex,
        inputs.body
      );
    }).toThrow();
  });

  it('should fail if DKIM message (headers) is tampered with', async () => {
    // Tamper with the headers bytes
    const tamperedHeadersBytes = Bytes.from([
      ...inputs.headers.bytes,
      UInt8.from(1),
    ]);
    expect(() => {
      emailVerify(
        tamperedHeadersBytes,
        inputs.signature,
        inputs.publicKey,
        inputs.modulusLength,
        false,
        inputs.bodyHashIndex,
        inputs.body
      );
    }).toThrow();
  });

  it('should fail if the email body is tampered with', async () => {
    // Modify the last byte to tamper with the email body
    const tamperedBodyBytes = Bytes.from([...inputs.body.bytes, UInt8.from(1)]);
    expect(() => {
      emailVerify(
        inputs.headers,
        inputs.signature,
        inputs.publicKey,
        inputs.modulusLength,
        true, // Enable body hash check since we are tampering with the body
        inputs.bodyHashIndex,
        tamperedBodyBytes
      );
    }).toThrow();
  });

  it('should fail if the email bodyHashIndex is false', async function () {
    // Tamper with the body hash
    const falseBodyHashIndex = inputs.bodyHashIndex.add(Field.random());
    expect(() => {
      emailVerify(
        inputs.headers,
        inputs.signature,
        inputs.publicKey,
        inputs.modulusLength,
        true, // Enable body hash check since we are tampering with the body hash
        falseBodyHashIndex,
        inputs.body
      );
    }).toThrow();
  });
});
