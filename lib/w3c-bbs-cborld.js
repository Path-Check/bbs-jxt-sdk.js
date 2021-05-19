import { documentLoader } from './documentLoader'

import {
  Bls12381G2KeyPair,
  BbsBlsSignature2020,
  BbsBlsSignatureProof2020,
  deriveProof
} from "@mattrglobal/jsonld-signatures-bbs"

import jsigs from "jsonld-signatures";
import jsonxt from "jsonxt";

import templates from "./jxt-templates/EUDGC"

export async function sign(certificate, keyPairSerialized) {
    const keyPair = await new Bls12381G2KeyPair(keyPairSerialized);
    const suite = new BbsBlsSignature2020({ key: keyPair });

    var issue = new Date();
    var year = issue.getFullYear();
    var month = issue.getMonth();
    var day = issue.getDate();
    var exp = new Date(year + 2, month, day);

    const credential = {
        issuer: keyPairSerialized.controller,
        issuanceDate: issue.toISOString().replace(/....Z$/, "Z"),
        expirationDate: exp.toISOString().replace(/....Z$/, "Z"),
        ...certificate
    };

    return await jsigs.sign(
      credential, {
        suite, 
        purpose: new jsigs.purposes.AssertionProofPurpose(), 
        documentLoader
      }
    );
}

export async function verify(credential) {
    let verification = await jsigs.verify(credential, {
      suite: new BbsBlsSignature2020(),
      purpose: new jsigs.purposes.AssertionProofPurpose(),
      documentLoader
    });

    return verification.verified;
}

export async function unpack(uri) {
    return await jsonxt.unpack(uri, resolver => {
      return JSON.parse(JSON.stringify(templates));
    });
}    

export async function pack(signedData) {
    const version = "1"
    const resolver = "pathcheck.org"
    var type = ""

    const sJSON = JSON.stringify(signedData);
    if (sJSON.includes("DGCProofOfCovidTest"))
      type = "eu.dgc.test";
    if (sJSON.includes("DGCProofOfVaccination"))
      type = "eu.dgc.vax";
    if (sJSON.includes("DGCProofOfRecovery"))
      type = "eu.dgc.recv";

    const uri = await jsonxt.pack(signedData, JSON.parse(JSON.stringify(templates)), type, version, resolver, {
        uppercase: true,
    });

    return uri;
}

export async function signAndPack(payload, did) {
  return await pack(await sign(payload, did));
}

export async function unpackAndVerify(uri) {
  try {
    const json = await unpack(uri);
    if (await verify(json)) {
      delete json["proof"];
      return json;
    }
    return undefined;
  } catch (err) {
    console.log(err);
    return undefined;
  }
}
