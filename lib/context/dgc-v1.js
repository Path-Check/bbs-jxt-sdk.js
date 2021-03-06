export default {
  "@context": {
    "@version": 1.1,
    "name": "http://schema.org/name",
    "description": "http://schema.org/description",
    "identifier": "http://schema.org/identifier",
    "image": {
      "@id": "http://schema.org/image",
      "@type": "@id"
    },
    "id": "@id",
    "type": "@type",
    "DGCCertificate": {
      "@id": "https://w3id.org/dgc#DGCCertificate",
      "@context": {
        "proofOfVaccination": {
          "@id": "https://w3id.org/dgc#DGCProofOfVaccination"
        },
        "proofOfCovidTest": {
          "@id": "https://w3id.org/dgc#DGCProofOfCovidTest"
        },
        "proofOfRecovery": {
          "@id": "https://w3id.org/dgc#DGCProofOfRecovery"
        },
        "personalInformation": {
          "@id": "https://w3id.org/dgc#DGCSubject"
        }
      }
    },
    "DGCProofOfVaccination": {
      "@id": "https://w3id.org/dgc#DGCProofOfVaccination",
      "@context": {
        "issuerName": {
          "@id": "http://hl7.org/fhir/uv/ips/Immunization.location.name"
        },
        "countryOfVaccination": {
          "@id": "http://hl7.org/fhir/ValueSet/iso3166-1-2"
        },
        "vaccinationInformation": {
          "@id": "https://w3id.org/dgc#DGCVaccinationInformation"
        }
      }
    },
    "DGCProofOfCovidTest": {
      "@id": "https://w3id.org/dgc#DGCProofOfCovidTest",
      "@context": {
        "issuerName": {
          "@id": "http://hl7.org/fhir/uv/ips/Immunization.location.name"
        },
        "countryOfTestAdminstration": {
          "@id": "https://schema.org/countryOfOrigin"
        },
        "testInformation": {
          "@id": "https://w3id.org/dgc#DGCTestInformation"
        }
      }
    },
    "DGCProofOfRecovery": {
      "@id": "https://w3id.org/dgc#DGCProofOfRecovery",
      "@context": {
        "issuerName": {
          "@id": "http://hl7.org/fhir/uv/ips/Immunization.location.name"
        },
        "countryOfTest": {
          "@id": "https://schema.org/countryOfOrigin"
        },
        "infectionInformation": {
          "@id": "https://w3id.org/dgc#DGCInfectionInformation"
        }
      }
    },
    "DGCVaccinationInformation": {
      "@id": "https://w3id.org/dgc#DGCVaccinationInformation",
      "@context": {
        "administeringCentre": {
          "@id": "http://hl7.org/fhir/uv/ips/Immunization.location.name"
        },
        "batchNumber": {
          "@id": "http://hl7.org/fhir/uv/ips/Immunization.lotNumber"
        },
        "dateOfVaccination": {
          "@id": "http://hl7.org/fhir/uv/ips/Immunization.occurenceDateTime"
        },
        "nextVaccinationDate": {
          "@id": "http://hl7.org/fhir/ImmunizationRecommendation.dateCriterion.value"
        },
        "order": {
          "@id": "http://hl7.org/fhir/Immunization.protocolApplied.doseNumber"
        },
        "dose": {
          "@id": "http://hl7.org/fhir/Immunization.protocolApplied.doseNumber"
        },
        "totalDoses": {
          "@id": "http://hl7.org/fhir/Immunization.protocolApplied.totalDoses"
        },
        "code": {
          "@id": "http://hl7.org/fhir/uv/ips/Immunization.lotNumber"
        },
        "targetDisease": {
          "@id": "http://hl7.org/fhir/uv/ips/Immunization.lotNumber"
        },
        "marketingAuthHolder": {
          "@id": "http://hl7.org/fhir/uv/ips/Immunization.lotNumber"
        },
        "medicinalProductName": {
          "@id": "http://hl7.org/fhir/uv/ips/Immunization.lotNumber"
        },
        "diseaseProtectedFrom": {
          "@id": "http://snomed.info/sct/840539006"
        },
        "prophylaxis": {
          "@id": "http://snomed.info/sct/840539006"
        }
      }
    },
    "DGCTestInformation": {
      "@id": "https://w3id.org/dgc#DGCTestInformation",
      "@context": {
        "testName": {
          "@id": "http://hl7.eu/fhir/ig/dgc/ValueSet/loinc-tests-covid-19"
        },
        "diseaseTestedFrom": {
          "@id": "http://snomed.info/sct/840539006"
        },
        "testType": {
          "@id": "http://hl7.eu/fhir/ig/dgc/ValueSet/covid-19-lab-methods"
        },
        "sampleOriginType": {
          "@id": "http://hl7.org/fhir/ValueSet/body-site"
        },
        "sampleCollectionDateTime": {
          "@id": "http://hl7.eu/fhir/ig/dgc/DiagnosticReport.specimen.collectedDateTime"
        },
        "testManufacturer": {
          "@id": "https://schema.org/manufacturer"
        },
        "testResultDate": {
          "@id": "http://hl7.eu/fhir/ig/dgc/DiagnosticReport.resultDate"
        },
        "testResult": {
          "@id": "http://hl7.org/fhir/ValueSet/observation-interpretation"
        },
        "testCenter": {
          "@id": "http://hl7.eu/fhir/ig/dgc/StructureDefinition/Location-dgc"
        },
        "testValidatorId": {
          "@id": "http://hl7.eu/fhir/ig/dgc/DiagnosticReport.resultsIntepreter"
        },
        "healthProfessionalAdministered": {
          "@id": "http://hl7.org/fhir/uv/ips/StructureDefinition/Practitioner-uv-ips"
        },
        "testDetails": {
          "@id": "http://hl7.org/fhir/uv/ips/StructureDefinition/Observation-results-pathology-uv-ips"
        },
      }
    },
    "DGCInfectionInformation": {
      "@id": "https://w3id.org/dgc#DGCInfectionInformation",
      "@context": {
        "diseaseRecoveredFrom": {
          "@id": "http://snomed.info/sct/840539006"
        },
        "dateFirstPositive": {
          "@id": "http://hl7.eu/fhir/ig/dgc/DiagnosticReport.result.effectiveDateTime"
        },
        "validFrom": {
          "@id": "https://schema.org/validFrom"
        },
        "validUntil": {
          "@id": "https://schema.org/validUntil"
        }
      }
    },
    "DGCSubject": {
      "@id": "https://w3id.org/dgc#DGCSubject",
      "@context": {
        "familyName": {
          "@id": "http://hl7.eu/fhir/ig/dgc/Patient.name.familyName"
        },
        "givenName": {
          "@id": "http://hl7.eu/fhir/ig/dgc/Patient.name.givenName"
        },
        "stdFamilyName": {
          "@id": "http://hl7.eu/fhir/ig/dgc/Patient.name.familyName"
        },
        "stdGivenName": {
          "@id": "http://hl7.eu/fhir/ig/dgc/Patient.name.givenName"
        },
        "birthDate": {
          "@id": "http://hl7.eu/fhir/ig/dgc/Patient.birthDate"
        }
      }
    }
  }
}