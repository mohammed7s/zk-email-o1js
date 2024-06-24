# How to use zkemail o1js 

## Installation 

- o1js; make sure its latest version 
- npm install... 

## How to use 

In order to verify if a given user has an eml file that validates the required constraints, you need to specify the exact regex circuit that will look for matching characters (step1) and specify how the domain public key is validated and the action it unlocks (step2), and finally the user needs to prepare their email file and generate inputs to the app (step3).  

### step1: create your regex circuit 
Generate desired regex: How to produce the regex zkProgram/ logic 

### step2: write your zkapp 

specify the publickey of domain onchain: This can be done either: 
    a. Hardcode
    b. setup a dkim registry onchain with permissions to specific parties 
    c. dns registry oracle 

For this guide we will simply use a. 


### step3: Generate inputs 

You might be wondering why dont we simply feed the whole eml file as in input to the app. In particular that o1js apps generate proofs on the client side. So why do we need to process it? 

- we need to retrieve the public key from a DNS registry for a given domain 
- we need to have the data in a provable format. Its easier if we process it offchain 
- it will take less time for the prover 

1. Download the eml file 

Most web email clients allow you to download the eml file. See this guides: 
- gmail: 
- hotmail: 


2. generate inputs 

Note that the generate inputs function is a wrapper for the helpers of the zkemail library. We have decided to use those helpers because their code is audited and we do not need to recreate the work from scratch for our application. 


Note: this preprocessing of the input will happen on the user side that is interacting with the app. As an app developer you might want to incorporate these functionality on the frontend for the user. 



