export default {
  "ghpt:1": {
    "columns": [
      {"path": "issuanceDate", "encoder": "string"},
      {"path": "expirationDate", "encoder": "string"},
      {"path": "issuer", "encoder": "string"},
      {"path": "id", "encoder": "string"},
      {"path": "credentialSubject.id", "encoder": "string"},
      {"path": "credentialSubject.issuerName", "encoder": "string"},
      {"path": "credentialSubject.testInformation.testType", "encoder": "string"},
      {"path": "credentialSubject.testInformation.testResult", "encoder": "string"},
      {"path": "credentialSubject.testInformation.testCenter", "encoder": "string"},
      {"path": "credentialSubject.testInformation.diseaseTestedFrom", "encoder": "string"},
      {"path": "credentialSubject.testInformation.testName", "encoder": "string"},
      {"path": "credentialSubject.testInformation.testManufacturer", "encoder": "string"},
      {"path": "credentialSubject.testInformation.sampleCollectionDateTime", "encoder": "string"},
      {"path": "credentialSubject.testInformation.testResultDate", "encoder": "string"},
      {"path": "credentialSubject.testInformation.testValidatorId", "encoder": "string"},
      {"path": "credentialSubject.testInformation.countryOfTestAdminstration", "encoder": "string"},
      {"path": "credentialSubject.personalInformation.familyName", "encoder": "string"},
      {"path": "credentialSubject.personalInformation.givenName", "encoder": "string"},
      {"path": "credentialSubject.personalInformation.stdFamilyName", "encoder": "string"},
      {"path": "credentialSubject.personalInformation.stdGivenName", "encoder": "string"},
      {"path": "credentialSubject.personalInformation.birthDate", "encoder": "isodate-1900-base32"},
      {"path": "credentialSubject.personalInformation.gender", "encoder": "string"},
      {"path": "proof.created", "encoder": "isodatetime-epoch-base32"},
      {"path": "proof.proofValue", "encoder": "string"},
      {"path": "proof.verificationMethod", "encoder": "string"}
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
        "type": "DGCProofOfCovidTest",
        "testInformation": {
          "@context": [
              "https://w3id.org/pathogen/v1"
          ],          
          "type": "DGCTestInformation"
        },
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
  "ghpv:1": {
    "columns": [
      {"path": "issuanceDate", "encoder": "string"},
      {"path": "expirationDate", "encoder": "string"},
      {"path": "issuer", "encoder": "string"},
      {"path": "id", "encoder": "string"},
      {"path": "credentialSubject.id", "encoder": "string"},
      {"path": "credentialSubject.issuerName", "encoder": "string"},
      {"path": "credentialSubject.vaccinationInformation.diseaseProtectedFrom", "encoder": "string"},
      {"path": "credentialSubject.vaccinationInformation.prophylaxis", "encoder": "string"},
      {"path": "credentialSubject.vaccinationInformation.countryOfVaccination", "encoder": "string"},
      {"path": "credentialSubject.vaccinationInformation.dateOfVaccination", "encoder": "string"},
      {"path": "credentialSubject.vaccinationInformation.order", "encoder": "string"},
      {"path": "credentialSubject.vaccinationInformation.vaccine.code", "encoder": "string"},
      {"path": "credentialSubject.vaccinationInformation.vaccine.marketingAuthHolder", "encoder": "string"},
      {"path": "credentialSubject.vaccinationInformation.vaccine.medicinalProductName", "encoder": "string"},
      {"path": "credentialSubject.personalInformation.familyName", "encoder": "string"},
      {"path": "credentialSubject.personalInformation.givenName", "encoder": "string"},
      {"path": "credentialSubject.personalInformation.stdFamilyName", "encoder": "string"},
      {"path": "credentialSubject.personalInformation.stdGivenName", "encoder": "string"},
      {"path": "credentialSubject.personalInformation.birthDate", "encoder": "isodate-1900-base32"},
      {"path": "credentialSubject.personalInformation.gender", "encoder": "string"},
      {"path": "proof.created", "encoder": "isodatetime-epoch-base32"},
      {"path": "proof.proofValue", "encoder": "string"},
      {"path": "proof.verificationMethod", "encoder": "string"}
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
        "type": "DGCProofOfVaccination",
        "vaccinationInformation": {
          "@context": [
              "https://w3id.org/pathogen/v1"
          ],          
          "type": "DGCVaccinationInformation", 
          "vaccine": {
              "@context": [
                  "https://w3id.org/pathogen/v1"
              ],
              "type": "DGCVaccine",
          }
        },
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
  "ghpr:1": {
    "columns": [
      {"path": "issuanceDate", "encoder": "string"},
      {"path": "expirationDate", "encoder": "string"},
      {"path": "issuer", "encoder": "string"},
      {"path": "id", "encoder": "string"},
      {"path": "credentialSubject.id", "encoder": "string"},
      {"path": "credentialSubject.issuerName", "encoder": "string"},
      {"path": "credentialSubject.validFrom", "encoder": "string"},
      {"path": "credentialSubject.validUntil", "encoder": "string"},
      {"path": "credentialSubject.infectionInformation.diseaseRecoveredFrom", "encoder": "string"},
      {"path": "credentialSubject.infectionInformation.dateFirstPositive", "encoder": "string"},
      {"path": "credentialSubject.infectionInformation.countryOfTest", "encoder": "string"},
      {"path": "credentialSubject.personalInformation.familyName", "encoder": "string"},
      {"path": "credentialSubject.personalInformation.givenName", "encoder": "string"},
      {"path": "credentialSubject.personalInformation.stdFamilyName", "encoder": "string"},
      {"path": "credentialSubject.personalInformation.stdGivenName", "encoder": "string"},
      {"path": "credentialSubject.personalInformation.birthDate", "encoder": "isodate-1900-base32"},
      {"path": "credentialSubject.personalInformation.gender", "encoder": "string"},
      {"path": "proof.created", "encoder": "isodatetime-epoch-base32"},
      {"path": "proof.proofValue", "encoder": "string"},
      {"path": "proof.verificationMethod", "encoder": "string"}
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
        "type": "DGCProofOfRecovery",
        "infectionInformation": {
          "@context": [
              "https://w3id.org/pathogen/v1"
          ],          
          "type": "DGCInfectionInformation", 
        },
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
  }
};