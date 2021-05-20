const {sign, verify, pack, unpack, signAndPack, unpackAndVerify, addCache} = require('../lib/index');
const expect = require('chai').expect; 
const bs58 = require('bs58');

const { Bls12381G2KeyPair } = require("@mattrglobal/jsonld-signatures-bbs")

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
    "type": "DGCProofOfCovidTest",
    "testInformation": {
      "@context": [
        "https://w3id.org/pathogen/v1"
      ],
      "type": "DGCTestInformation",
      "testType": "loinc#LP217198-3",
      "testResult": "POS",
      "testCenter": "Hospital Na Františku Prague",
      "testValidatorId": "test-id",
      "countryOfTestAdminstration": "it"
    },
    "personalInformation": {
      "@context": [
        "https://w3id.org/pathogen/v1"
      ],
      "type": "DGCSubject",
      "familyName": "Schmidt",
      "givenName": "Abdiel",
      "birthDate": "1987-07-07",
      "gender": "F"
    }
  }
};

const SIGNED_TEST_PAYLOAD = {
  issuer: 'did:web:PCF.PW:1A8',
  issuanceDate: '2021-05-20T18:30:46Z',
  expirationDate: '2023-05-20T04:00:00Z',
  '@context': [
    'https://www.w3.org/2018/credentials/v1',
    'https://w3id.org/pathogen/v1',
    'https://w3id.org/security/bbs/v1'
  ],
  type: [ 'VerifiableCredential' ],
  credentialSubject: {
    '@context': [ 'https://w3id.org/pathogen/v1' ],
    type: 'DGCProofOfCovidTest',
    testInformation: {
      '@context': [
        "https://w3id.org/pathogen/v1"
      ],
      type: 'DGCTestInformation',
      testType: 'loinc#LP217198-3',
      testResult: 'POS',
      testCenter: 'Hospital Na Františku Prague',
      testValidatorId: 'test-id',
      countryOfTestAdminstration: 'it'
    },
    personalInformation: {
      '@context': [
        "https://w3id.org/pathogen/v1"
      ],
      type: 'DGCSubject',
      familyName: 'Schmidt',
      givenName: 'Abdiel',
      birthDate: '1987-07-07',
      gender: 'F'
    }
  },
  proof: {
    type: 'BbsBlsSignature2020',
    created: '2021-05-20T18:30:46Z',
    proofPurpose: 'assertionMethod',
    proofValue: 'iaIx3/VJamQdbvxapcMfch507pZDSuqu3SALH5Qzf3GsGV4Ymq/gwlsywxyQ+UaHUcqWakcL+OnfDazoP3DzejdW54EtGLFTAlIJBz+rSTw6vCWq7Q8dPw41scYcWW7Ky2PIPEQjmNnsoy423auGzQ==',
    verificationMethod: 'did:web:PCF.PW:1A8#web'
  }
};

const mockKeyPair = {
  id: "did:web:PCF.PW:1A8#web",
  controller: "did:web:PCF.PW:1A8",
  privateKeyBase58: "5D6Pa8dSwApdnfg7EZR8WnGfvLDCZPZGsZ5Y1ELL9VDj",
  publicKeyBase58: "oqpWYKaZD9M1Kbe94BVXpr8WTdFBNZyKv48cziTiQUeuhm7sBhCABMyYG4kcMrseC68YTFFgyhiNeBKjzdKk9MiRWuLv5H4FFujQsQK2KTAtzU8qTBiZqBHMmnLF4PL7Ytu"
}

addCache(mockKeyPair);

describe('BBS Crypto', function() {
  it('should sign the package', async function() {
    const signed = await sign(TEST_PAYLOAD, mockKeyPair);
    expect(signed).to.not.be.null;
    expect(signed.proof).to.not.be.null;
    expect(signed.issuer).to.not.be.null;
    expect(signed.issuanceDate).to.not.be.null;
  });

  it('should verify the package', async function() {
    const result = await verify(SIGNED_TEST_PAYLOAD);
    expect(result).to.be.true;
  });

  it('should sign and verify the package with new ramdom key', async function() {
    const privateKey = await Bls12381G2KeyPair.generate({id: "did:example:489398594#test2", controller: "did:example:489398594"});

    const keyPair = {
        id: privateKey.id,
        controller: privateKey.controller,
        privateKeyBase58: bs58.encode(privateKey.privateKeyBuffer),
        publicKeyBase58: bs58.encode(privateKey.publicKeyBuffer)
    }

    addCache(keyPair);
  
    const signed = await sign(TEST_PAYLOAD, keyPair);
    const result = await verify(signed);
    expect(result).to.be.true;
  });
});


describe('BBS Data Minimization', function() {
  it('should pack And unpack', async function() {
    const packed = await pack(SIGNED_TEST_PAYLOAD, "pcf.pw", "dgc.test", "1");
    const unpacked = await unpack(packed);
    expect(unpacked).to.eql(SIGNED_TEST_PAYLOAD);
  });
});

describe('BBS Soup to Nuts', function() {
  it('should Sign Pack And Unpack Verify JSON', async function() {
    const uri = await signAndPack(TEST_PAYLOAD, mockKeyPair, "pcf.pw", "dgc.test", "1");
    const resultJSON = await unpackAndVerify(uri);

    expect(resultJSON.proof).to.not.be.null;
    expect(resultJSON.issuer).to.not.be.null;
    expect(resultJSON.issuanceDate).to.not.be.null;

    // Removing added elements to match initial payload. 
    resultJSON["@context"] = resultJSON["@context"].filter(function(item) {
        return item !== "https://w3id.org/security/suites/ed25519-2020/v1"
    })
    delete resultJSON["issuanceDate"]; // These change when tests run
    delete resultJSON["expirationDate"]; // These change when tests run
    delete resultJSON["issuer"]; // These change when tests run
    expect(resultJSON).to.eql(TEST_PAYLOAD);
  });
});

const DGCProofOfRecovery = {
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
    "type": "DGCProofOfRecovery",
    "id": "urn:uvci:01:NL:LSP/REC/1289821",
    "infectionInformation": {
      "@context": [
        "https://w3id.org/pathogen/v1"
      ],
      "type": "DGCInfectionInformation",
      "countryOfTest": "NL",
      "dateFirstPositive": "2021-04-21",
      "diseaseRecoveredFrom": "840539006"
    },
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
    "validFrom": "2021-05-01",
    "validUntil": "2021-10-21"
  }
}

const DGCProofOfCovidTest = {
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
    "type": "DGCProofOfCovidTest",
    "id": "urn:uvci:01:NL:GGD/81AAH16AZ",
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
    "testInformation": {
      "@context": [
        "https://w3id.org/pathogen/v1"
      ],
      "type": "DGCTestInformation",
      "countryOfTestAdminstration": "NL",
      "diseaseTestedFrom": "840539006",
      "sampleCollectionDateTime": "2021-04-13T14:20:00Z",
      "testCenter": "GGD FryslÃ¢n, L-Heliconweg",
      "testManufacturer": "1232",
      "testName": "COVID PCR",
      "testResult": "260415000",
      "testResultDate": "2021-04-13T14:40:01Z",
      "testType": "LP217198-3"
    }
  }
}

const DGCProofOfVaccination = {
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
      "dose": 2,
      "totalDoses": 2,
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
}

describe('DGC Soup to Nuts', function() { 
  it('should Sign Pack And Unpack Verify DGCProofOfRecovery', async function() {
    const uri = await signAndPack(DGCProofOfRecovery, mockKeyPair,"pcf.pw", "dgc.recv", "1");
    const resultJSON = await unpackAndVerify(uri);

    expect(resultJSON.proof).to.not.be.null;
    expect(resultJSON.issuer).to.not.be.null;
    expect(resultJSON.issuanceDate).to.not.be.null;

    // Removing added elements to match initial payload. 
    resultJSON["@context"] = resultJSON["@context"].filter(function(item) {
        return item !== "https://w3id.org/security/suites/ed25519-2020/v1"
    })
    delete resultJSON["issuanceDate"]; // These change when tests run
    delete resultJSON["expirationDate"]; // These change when tests run
    delete resultJSON["issuer"]; // These change when tests run
    expect(resultJSON).to.eql(DGCProofOfRecovery);
  });
  
  it('should Sign Pack And Unpack Verify DGCProofCOVIDTest', async function() {
    const uri = await signAndPack(DGCProofOfCovidTest, mockKeyPair,"pcf.pw", "dgc.test", "1");
    const resultJSON = await unpackAndVerify(uri);

    expect(resultJSON.proof).to.not.be.null;
    expect(resultJSON.issuer).to.not.be.null;
    expect(resultJSON.issuanceDate).to.not.be.null;

    // Removing added elements to match initial payload. 
    resultJSON["@context"] = resultJSON["@context"].filter(function(item) {
        return item !== "https://w3id.org/security/suites/ed25519-2020/v1"
    })
    delete resultJSON["issuanceDate"]; // These change when tests run
    delete resultJSON["expirationDate"]; // These change when tests run
    delete resultJSON["issuer"]; // These change when tests run
    expect(resultJSON).to.eql(DGCProofOfCovidTest);
  });

  it('should Sign Pack And Unpack Verify DGCProofOfVaccination', async function() {
    const uri = await signAndPack(DGCProofOfVaccination, mockKeyPair, "pcf.pw", "dgc.vax", "1");
    const resultJSON = await unpackAndVerify(uri);

    expect(resultJSON.proof).to.not.be.null;
    expect(resultJSON.issuer).to.not.be.null;
    expect(resultJSON.issuanceDate).to.not.be.null;

    // Removing added elements to match initial payload. 
    resultJSON["@context"] = resultJSON["@context"].filter(function(item) {
        return item !== "https://w3id.org/security/suites/ed25519-2020/v1"
    })
    delete resultJSON["issuanceDate"]; // These change when tests run
    delete resultJSON["expirationDate"]; // These change when tests run
    delete resultJSON["issuer"]; // These change when tests run
    expect(resultJSON).to.eql(DGCProofOfVaccination);
  });
  
});
