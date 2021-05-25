export default {
  "dgc:1": {
    "columns": [
      {"path": "credentialSubject.personalInformation.familyName", "encoder": "string"},
      {"path": "credentialSubject.personalInformation.givenName", "encoder": "string"},
      {"path": "credentialSubject.personalInformation.stdFamilyName", "encoder": "string"},
      {"path": "credentialSubject.personalInformation.stdGivenName", "encoder": "string"},
      {"path": "credentialSubject.personalInformation.birthDate", "encoder": "isodate-1900-base32"},
      {"path": "credentialSubject.personalInformation.gender", "encoder": "string"},

      {"path": "credentialSubject.proofOfVaccination", encoder: "array", encoder_param: "dgc.vaxComponent:1" },
      {"path": "credentialSubject.proofOfCovidTest", encoder: "array", encoder_param: "dgc.testComponent:1" },
      {"path": "credentialSubject.proofOfRecovery", encoder: "array", encoder_param: "dgc.recvComponent:1" },
      
      {"path": "issuanceDate", "encoder": "isodatetime-epoch-base32"},
      {"path": "expirationDate", "encoder": "isodatetime-epoch-base32"},
      {"path": "issuer", "encoder": "did:web"},
      {"path": "id", "encoder": "string"},
      {"path": "proof.created", "encoder": "isodatetime-epoch-base32"},
      {"path": "proof.proofValue", "encoder": "base64-base32"},
      {"path": "proof.verificationMethod", "encoder": "did:web"}
    ],
    "template": {
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
        "type": "DGCCertificate",
        "personalInformation": {
          "@context": [
              "https://w3id.org/pathogen/v1"
          ],
          "type": "DGCSubject"
        }
      },
      "proof": {
        "type": "BbsBlsSignature2020",
        "proofPurpose": "assertionMethod"
      }
    }
  }, 
  "dgc.testComponent:1": {
    "columns": [
      {"path": "credentialSubject.id", "encoder": "urn:uvci"},
      {"path": "credentialSubject.issuerName", "encoder": "string"},
      {"path": "credentialSubject.testInformation.countryOfTestAdminstration", "encoder": "string"},
      {"path": "credentialSubject.testInformation.testType", "encoder": "string"},
      {"path": "credentialSubject.testInformation.testResult", "encoder": "string"},
      {"path": "credentialSubject.testInformation.testCenter", "encoder": "string"},
      {"path": "credentialSubject.testInformation.diseaseTestedFrom", "encoder": "string"},
      {"path": "credentialSubject.testInformation.testName", "encoder": "string"},
      {"path": "credentialSubject.testInformation.testManufacturer", "encoder": "string"},
      {"path": "credentialSubject.testInformation.sampleCollectionDateTime", "encoder": "isodatetime-epoch-base32"},
      {"path": "credentialSubject.testInformation.testResultDate", "encoder": "isodatetime-epoch-base32"},
      {"path": "credentialSubject.testInformation.testValidatorId", "encoder": "string"},
    ],
    "template": {
      "@context": [
        "https://w3id.org/pathogen/v1"
      ],
      "type": "DGCProofOfCovidTest",
      "testInformation": {
        "@context": [
            "https://w3id.org/pathogen/v1"
        ],          
        "type": "DGCTestInformation", 
      }
    }
  },
  "dgc.vaxComponent:1": {
    "columns": [
      {"path": "credentialSubject.id", "encoder": "urn:uvci"},
      {"path": "credentialSubject.issuerName", "encoder": "string"},
      {"path": "credentialSubject.countryOfVaccination", "encoder": "string"},
      {"path": "credentialSubject.vaccinationInformation.diseaseProtectedFrom", "encoder": "string"},
      {"path": "credentialSubject.vaccinationInformation.prophylaxis", "encoder": "string"},
      {"path": "credentialSubject.vaccinationInformation.dateOfVaccination", "encoder": "isodate-1900-base32"},
      {"path": "credentialSubject.vaccinationInformation.dose", "encoder": "integer-base32"},
      {"path": "credentialSubject.vaccinationInformation.totalDoses", "encoder": "integer-base32"},
      {"path": "credentialSubject.vaccinationInformation.code", "encoder": "string"},
      {"path": "credentialSubject.vaccinationInformation.marketingAuthHolder", "encoder": "string"},
      {"path": "credentialSubject.vaccinationInformation.medicinalProductName", "encoder": "string"},
    ],
    "template": {
      "@context": [
        "https://w3id.org/pathogen/v1"
      ],
      "type": "DGCProofOfVaccination",
      "vaccinationInformation": {
        "@context": [
            "https://w3id.org/pathogen/v1"
        ],          
        "type": "DGCVaccinationInformation", 
      }
    }
  }, 
  "dgc.recvComponent:1": {
    "columns": [
      {"path": "credentialSubject.id", "encoder": "urn:uvci"},
      {"path": "credentialSubject.issuerName", "encoder": "string"},
      {"path": "credentialSubject.countryOfTest", "encoder": "string"},
      {"path": "credentialSubject.infectionInformation.validFrom", "encoder": "isodate-1900-base32"},
      {"path": "credentialSubject.infectionInformation.validUntil", "encoder": "isodate-1900-base32"},
      {"path": "credentialSubject.infectionInformation.diseaseRecoveredFrom", "encoder": "string"},
      {"path": "credentialSubject.infectionInformation.dateFirstPositive", "encoder": "isodate-1900-base32"},
    ],
    "template": {
      "type": "DGCProofOfRecovery",
      "infectionInformation": {
        "@context": [
            "https://w3id.org/pathogen/v1"
        ],          
        "type": "DGCInfectionInformation", 
      },
    }
  }
};