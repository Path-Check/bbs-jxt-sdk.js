import { documentLoader } from './documentLoader'

import {
  Bls12381G2KeyPair,
  BbsBlsSignature2020,
  BbsBlsSignatureProof2020,
  deriveProof
} from "@mattrglobal/jsonld-signatures-bbs"

import jsigs from "jsonld-signatures";
import jsonxt from "jsonxt";

export async function sign(certificate, keyPairSerialized) {
    const keyPair = await new Bls12381G2KeyPair(keyPairSerialized);
    const suite = new BbsBlsSignature2020({ key: keyPair });

    const credential = {
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
    return await jsonxt.unpack(uri, jsonxt.resolveCache);
}    

export async function pack(signedData, domain, templateName, templateVersion) {
    const uri = await jsonxt.resolvePack(signedData, templateName, templateVersion, domain, jsonxt.resolveCache, {
        uppercase: true,
    });

    return uri;
}

export async function signAndPack(payload, keyPairSerialized, domain, templateName, templateVersion) {
  return await pack(await sign(payload, keyPairSerialized), domain, templateName, templateVersion);
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
