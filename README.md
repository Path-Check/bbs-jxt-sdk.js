# Verifiable QR SDK for BBS+ on JSON-XT Credentials

JavaScript Implementation of W3C Verifiable QR Credentials with BBS+ -> JSONXT -> QR. 

# Install

```sh
npm install @pathcheck/bbs-jxt-sdk --save
```

# Usage

## 1. Generating Keys

Generate private and public keys with: 

```js
npm run-script keys <YOUR_DOMAIN> <YOUR_KEY_NAME> <YOUR_CONTROLLER_NAME>
```

Example: 
```js
npm run-script keys  PCF.PW 1A10 WEB1
```
Returns: 
```
*******************************************************************************
Here are your SECRET keys. Key this private and use it to sign new packages.
*******************************************************************************
{
  id: 'did:web:PCF.PW:1A10',
  controller: 'did:web:PCF.PW:1A10#WEB1',
  privateKeyBase58: '3AmVDMSEiZ9s79fCrHHhTuYMGSfeHvbZ92NhMh3AqrxW',
  publicKeyBase58: 'yX1rjAqqRhUk8BTgVDdFn9buUZ59pmRpJouc8raqAXztwooW3Gs7Fsy8GhDWUdZkdEFjdDbGk925zMSQ6xkrCbwzUrDnzpe8sPLB7gi15Gva4zRN77GiqRgDLtjRDVkXmmv'
}


*************************************************************************************************************
Here are your PUBLIC DID document. Save this part as a .json and upload it to PCF.PW/1A10/did.json
*************************************************************************************************************
{
  '@context': 'https://w3id.org/security/v2',
  id: 'did:web:PCF.PW:1A10',
  assertionMethod: [
    {
      id: 'did:web:PCF.PW:1A10#WEB1',
      controller: 'did:web:PCF.PW:1A10',
      publicKeyBase58: 'yX1rjAqqRhUk8BTgVDdFn9buUZ59pmRpJouc8raqAXztwooW3Gs7Fsy8GhDWUdZkdEFjdDbGk925zMSQ6xkrCbwzUrDnzpe8sPLB7gi15Gva4zRN77GiqRgDLtjRDVkXmmv'
    }
  ],
  authentication: [
    {
      id: 'did:web:PCF.PW:1A10#WEB1',
      controller: 'did:web:PCF.PW:1A10',
      publicKeyBase58: 'yX1rjAqqRhUk8BTgVDdFn9buUZ59pmRpJouc8raqAXztwooW3Gs7Fsy8GhDWUdZkdEFjdDbGk925zMSQ6xkrCbwzUrDnzpe8sPLB7gi15Gva4zRN77GiqRgDLtjRDVkXmmv'
    }
  ]
}
```

## 2. Uploading Public Keys

Copy the second segment (PUBLIC DID DOCUMENT) as a JSON file to your `domain/keyName/did.json`

```json
{
  "@context": "https://w3id.org/security/v2",
  "id": "did:web:PCF.PW:1A10",
  "assertionMethod": [
    {
      "id": "did:web:PCF.PW:1A10#WEB1",
      "controller": "did:web:PCF.PW:1A10",
      "publicKeyBase58": "yX1rjAqqRhUk8BTgVDdFn9buUZ59pmRpJouc8raqAXztwooW3Gs7Fsy8GhDWUdZkdEFjdDbGk925zMSQ6xkrCbwzUrDnzpe8sPLB7gi15Gva4zRN77GiqRgDLtjRDVkXmmv"
    }
  ],
  "authentication": [
    {
      "id": "did:web:PCF.PW:1A10#WEB1",
      "controller": "did:web:PCF.PW:1A10",
      "publicKeyBase58": "yX1rjAqqRhUk8BTgVDdFn9buUZ59pmRpJouc8raqAXztwooW3Gs7Fsy8GhDWUdZkdEFjdDbGk925zMSQ6xkrCbwzUrDnzpe8sPLB7gi15Gva4zRN77GiqRgDLtjRDVkXmmv"
    }
  ]
}
```

The DID:WEB Resolver will point to that address (e.g. [`http://pcf.pw/1A10/did.json`](http://pcf.pw/1A10/did.json)) to download your public keys and verify the package. 

## 3. Preparing to Sign


With the keys: 

```js
const keyPair = {
  id: 'did:web:PCF.PW:1A10',
  controller: 'did:web:PCF.PW:1A10#WEB1',
  privateKeyBase58: '3AmVDMSEiZ9s79fCrHHhTuYMGSfeHvbZ92NhMh3AqrxW',
  publicKeyBase58: 'yX1rjAqqRhUk8BTgVDdFn9buUZ59pmRpJouc8raqAXztwooW3Gs7Fsy8GhDWUdZkdEFjdDbGk925zMSQ6xkrCbwzUrDnzpe8sPLB7gi15Gva4zRN77GiqRgDLtjRDVkXmmv'
}
```

And a JSON-LD Payload (We are using EU's Digital COVID Certificate as an example)

```js
const TEST_PAYLOAD = {
    "@context": ["https://www.w3.org/2018/credentials/v1", "https://w3id.org/dgc/v1", "https://w3id.org/security/bbs/v1"],
    "type": ["VerifiableCredential"],
    "credentialSubject": {
        "@context": ["https://w3id.org/dgc/v1"],
        "type": "DGCCertificate",
        "personalInformation": {
            "@context": ["https://w3id.org/dgc/v1"],
            "type": "DGCSubject",
            "familyName": "d'Arsøns - van Halen",
            "givenName": "François-Joan",
            "stdFamilyName": "DARSONS<VAN<HALEN",
            "stdGivenName": "FRANCOIS<JOAN",
            "birthDate": "2009-02-28"
        },
        "proofOfRecovery": [{
            "@context": ["https://w3id.org/dgc/v1"],
            "type": "DGCProofOfRecovery",
            "id": "urn:uvci:01:NL:LSP/REC/1289821",
            "issuerName": "Ministry of VWS",
            "countryOfTest": "NL",
            "infectionInformation": {
                "@context": ["https://w3id.org/dgc/v1"],
                "type": "DGCInfectionInformation",
                "diseaseRecoveredFrom": "840539006",
                "dateFirstPositive": "2021-04-21",
                "validFrom": "2021-05-01",
                "validUntil": "2021-10-21"
            }
        }],
        "proofOfVaccination": [{
            "@context": ["https://w3id.org/dgc/v1"],
            "type": "DGCProofOfVaccination",
            "id": "urn:uvci:01:NL:PlA8UWS60Z4RZXVALl6GAZ",
            "issuerName": "Ministry of VWS",
            "countryOfVaccination": "NL",
            "vaccinationInformation": {
                "@context": ["https://w3id.org/dgc/v1"],
                "type": "DGCVaccinationInformation",
                "diseaseProtectedFrom": "840539006",
                "prophylaxis": "1119349007",
                "dateOfVaccination": "2021-05-05",
                "dose": 1,
                "totalDoses": 2,
                "marketingAuthHolder": "ORG-100030215",
                "medicinalProductName": "EU/1/20/1528"
            }
        }, {
            "@context": ["https://w3id.org/dgc/v1"],
            "type": "DGCProofOfVaccination",
            "id": "urn:uvci:01:NL:ATS342XDYS358FDFH3GTK5",
            "issuerName": "Ministry of VWS",
            "countryOfVaccination": "NL",
            "vaccinationInformation": {
                "@context": ["https://w3id.org/dgc/v1"],
                "type": "DGCVaccinationInformation",
                "diseaseProtectedFrom": "840539006",
                "prophylaxis": "1119349007",
                "dateOfVaccination": "2021-05-25",
                "dose": 2,
                "totalDoses": 2,
                "marketingAuthHolder": "ORG-100030215",
                "medicinalProductName": "EU/1/20/1528"
            }
        }],
        "proofOfCovidTest": [{
            "@context": ["https://w3id.org/dgc/v1"],
            "type": "DGCProofOfCovidTest",
            "id": "urn:uvci:01:NL:GGD/81AAH16AZ",
            "issuerName": "Ministry of VWS",
            "countryOfTestAdminstration": "NL",
            "testInformation": {
                "@context": ["https://w3id.org/dgc/v1"],
                "type": "DGCTestInformation",
                "diseaseTestedFrom": "840539006",
                "testName": "COVID PCR",
                "testManufacturer": "1232",
                "testType": "LP217198-3",
                "sampleCollectionDateTime": "2021-02-13T14:20:00Z",
                "testResult": "260415000",
                "testCenter": "GGD Fryslân, L-Heliconweg"
            }
        }, {
            "@context": ["https://w3id.org/dgc/v1"],
            "type": "DGCProofOfCovidTest",
            "id": "urn:uvci:01:NL:GGD/23BBS36BC",
            "issuerName": "Ministry of VWS",
            "countryOfTestAdminstration": "NL",
            "testInformation": {
                "@context": ["https://w3id.org/dgc/v1"],
                "type": "DGCTestInformation",
                "diseaseTestedFrom": "840539006",
                "testName": "NAAT TEST",
                "testManufacturer": "1343",
                "testType": "LP6464-4",
                "sampleCollectionDateTime": "2021-04-13T14:20:00Z",
                "testResult": "260373001",
                "testCenter": "GGD Fryslân, L-Heliconweg"
            }
        }]
    }
};
```

Add keys to the Resolver Cache and call the signAndPack to create the URI for the QR Code: 

```js
const {signAndPack, unpackAndVerify} = require('@pathcheck/bbs-jxt.sdk');

const qrUri = await signAndPack(TEST_PAYLOAD, keyPair);
```

And call the unpack and verify to convert the URI into the payload: 

```js
const jsonld = await unpackAndVerify(qrUri);
```

# Development

```sh
npm install
``` 

# Test

```sh
npm test
```
