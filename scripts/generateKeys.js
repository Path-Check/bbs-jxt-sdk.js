const { Bls12381G2KeyPair } = require("@mattrglobal/jsonld-signatures-bbs");
const bs58 = require('bs58');

async function generatePublicKeyDidDocument(keyPair) {
  return {
    "@context": "https://w3id.org/security/v2",
    id: keyPair.id,
    assertionMethod: [ {  
      id: keyPair.controller,
      controller: keyPair.id,
      publicKeyBase58: keyPair.publicKeyBase58
    }],
    authentication: [ {  
      id: keyPair.controller,
      controller: keyPair.id,
      publicKeyBase58: keyPair.publicKeyBase58
    } ]
  };
} 

async function generateKeyPair(domainName, keyName, controllerName) {
  let keyId = `did:web:${domainName}:${keyName}`;
  let controllerId = `did:web:${domainName}:${keyName}#${controllerName}`

  const privateKey = await Bls12381G2KeyPair.generate({id: keyId, controller: controllerId});
  const keyPair = {
      id: privateKey.id,
      controller: privateKey.controller,
      privateKeyBase58: bs58.encode(privateKey.privateKeyBuffer),
      publicKeyBase58: bs58.encode(privateKey.publicKeyBuffer)
  }

  return keyPair;
}

async function generateInstructions(domainName, keyName, controllerName) {
  generateKeyPair(DOMAIN, KEY_NAME, CONTROLLER_NAME).then( keyPair => {
      generatePublicKeyDidDocument(keyPair).then( didDocument => {
        console.log("\n");
        console.log("*******************************************************************************");
        console.log("Here are your SECRET keys. Key this private and use it to sign new packages.");
        console.log("*******************************************************************************");
        console.log(keyPair);
        console.log("\n");
        console.log("*************************************************************************************************************");
        console.log(`Here are your PUBLIC DID document. Save this part as a .json and upload it to ${DOMAIN}/${KEY_NAME}/did.json`);
        console.log("*************************************************************************************************************");
        console.log(didDocument);
      });
    });
}

if (process.argv < 5) {
  console.log("3 arguments required: DOMAIN KEY_NAME CONTROLLER_NAME\nExample: node scripts/generateKeys.js PCF.PW 1A10 WEB")
} else {
  var [DOMAIN, KEY_NAME, CONTROLLER_NAME] = process.argv.slice(2);

  generateInstructions(DOMAIN.toUpperCase(), KEY_NAME.toUpperCase(), CONTROLLER_NAME.toUpperCase());
}



