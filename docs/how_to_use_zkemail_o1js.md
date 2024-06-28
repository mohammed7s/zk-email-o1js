# How to use zkemail o1js + tutorial 


In order to verify information from an email in an o1js application, we need to do the following steps: 

1. Generate the Regex circuit 
2. Write the smart contract logic
3. Integrate the input generate logic in the frontend  

In order to verify if a given user has an eml file that validates the required constraints, you need to specify the exact regex circuit that will look for matching characters (step1) and specify how the domain public key is validated and the action it unlocks (step2), and finally the user needs to prepare their email file and generate inputs to the app (step3).  




## Installation 

```
npm install zk-email-o1js
```


## step1: Generate regex circuit 

We need to specify the exact data we wish to capture in the email. We would also like to constraint it with the speficic of the email formatting to avoid cheating.  So for example, if the email format reveals the username on the third line after this sentence "recovery username for:" for example,  then we wish to restrict to only accept the input if it came after this specific sentence. Otherwise the user might try to use some user generated field that comes under "notes" field and pass on as an authentic username.  

The efficient way to define these patterns is by using regex patterns. If you have not heard of regex, its ok, all you need to know is that it is a way of communicating a speficic pattern that needs to searched while traversing the raw text. We will use the regex-o1js library to do it. Please read the README.md to get familiar with the regex concept. 

```
`git clone zk-regex-o1js` 
``` 

The steps we need to follow:  


1. Determine the regex pattern for your application. 

Each application will have its validation rules of the email content. If yu are new to the concept of regex, then these resources will help: . The bottom line is that we need to verify if someone actually hold

For the twitter example, we are looking for the username coming after this text : "password resets for @""

2. run the command 

``` 
npm run zk-regex 'password resets for @[A-Za-z0-9]+' '[A-Za-z0-9]+' 
```

This command will auto-generate the o1js code that will check the text for a defined pattern,  

we will wrap this logic in a function so we can use it in our app n the next step: 


```
function twitterInputRegex(input: UInt8[]) {
    <insert generated circuit code here> 
}
```


## step2: write your zkapp 

We now want to write the logic that would verify data from an email in a zkapp. 

1. Define how the public keys of your project 

In any real application the developer will have to decide on how the public key registry onchain will be managed. 

a. Hard coded? Yes but DNS records rotate often and might not be practical to upgrade the smart contracts regularly
b. create a dns oracle for Mina 
c. Give the onchain registry update previlages to specific process 


specify the publickey of domain onchain: This can be done either: 
    a. Hardcode
    b. setup a dkim registry onchain with permissions to specific parties 
    c. dns registry oracle 



Define the public key hash as a state variable 
why public key hash? 


![alt text](image.png)

```
class Twitter extends SmartContract {
  @state(Field) TwitterPublicKeyHash = State<Field>();

  init() {
    super.init();
    // Use the hash you computed earlier
    const computedHash = Hash.Poseidon.hash(inputs.publicKey.fields);
    this.TwitterPublicKeyHash.set(computedHash);
  }
```

2. call email verify function with body hash check 
or without 
What does this achieve?

3. call the regex function over the body input. 







Note: it doesnt matter whether this will be validated on the client side, or in a smart contract, in both cases the code needs to be provable.  




## step3: Generate inputs 

You might be wondering why dont we simply feed the whole eml file as in input to the app. In particular that o1js apps generate proofs on the client side. So why do we need to process it? 

- we need to retrieve the public key from a DNS registry for a given domain 
- we need to have the data in a provable format. Its easier if we process it offchain rather than deal with conversions onchain. 
- it will take less time for the prover 

1. Download the eml file 

Most web email clients allow you to download the eml file. See this guides: 
- gmail: 
- hotmail: 


2. generate inputs 

Note that the generate inputs function is a wrapper for the helpers of the zkemail library. We have decided to use those helpers because their code is audited and we do not need to recreate the work from scratch for our application. 


Note: this preprocessing of the input will happen on the user side that is interacting with the app. As an app developer you might want to incorporate these functionality on the frontend for the user. 

use tis line

```
import { generateInputs } from './generate-inputs.js';
```


```
const inputs = await generateInputs(rawEmail); 
```

