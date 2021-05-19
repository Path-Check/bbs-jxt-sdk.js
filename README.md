# Verifiable QR SDK for BBS+ on CBOR-LD Credentials

JavaScript Implementation of W3C Verifiable QR Credentials with BBS+ -> JSONXT -> QR. 

# Install

```sh
npm install divoc.sdk --save
```

# Usage

With the keys: 

```js
const keyPair = {
  id: "did:example:489398593#test",
  controller: "did:example:489398593",
  privateKeyBase58: "5D6Pa8dSwApdnfg7EZR8WnGfvLDCZPZGsZ5Y1ELL9VDj",
  publicKeyBase58: "oqpWYKaZD9M1Kbe94BVXpr8WTdFBNZyKv48cziTiQUeuhm7sBhCABMyYG4kcMrseC68YTFFgyhiNeBKjzdKk9MiRWuLv5H4FFujQsQK2KTAtzU8qTBiZqBHMmnLF4PL7Ytu"
}
```

And a JSON-LD Payload 

```js
const TEST_PAYLOAD = {
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://w3id.org/pathogen/v1",
    "https://w3id.org/security/bbs/v1"
  ],
  "type": [
    "VerifiableCredential"
  ],
  "credentialSubject": {
    "@context": [
      "https://w3id.org/pathogen/v1"
    ],
    "type": "DGCProofOfVaccination",
    "id": "urn:uvci:01:NL:PlA8UWS60Z4RZXVALl6GAZ",
    "issuerName": "Ministry of VWS",
    "personalInformation": {
      "@context": [
        "https://w3id.org/pathogen/v1"
      ],
      "type": "DGCSubject",
      "birthDate": "2009-02-28",
      "familyName": "d'ArsÃ¸ns - van Halen",
      "givenName": "FranÃ§ois-Joan",
      "stdFamilyName": "DARSONS<VAN<HALEN",
      "stdGivenName": "FRANCOIS<JOAN"
    },
    "vaccinationInformation": {
      "@context": [
        "https://w3id.org/pathogen/v1"
      ],
      "type": "DGCVaccinationInformation",
      "countryOfVaccination": "NL",
      "dateOfVaccination": "2021-05-18",
      "diseaseProtectedFrom": "840539006",
      "order": "2 of 2",
      "prophylaxis": "1119349007",
      "vaccine": {
        "@context": [
          "https://w3id.org/pathogen/v1"
        ],
        "type": "DGCVaccine",
        "code": "1119349007",
        "marketingAuthHolder": "ORG-100030215",
        "medicinalProductName": "EU/1/20/1528"
      }
    }
  }
};
```

Add keys to the Resolver Cache and call the signAndPack to create the URI for the QR Code: 

```js
const {sign, verify, pack, unpack, signAndPack, unpackAndVerify, addCache} = require('../lib/index');
addCache(mockKeyPair);

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
