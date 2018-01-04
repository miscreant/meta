// Copyright (C) 2017 Tony Arcieri, Dmitry Chestnykh
// MIT License. See LICENSE file for details.

import { suite, test } from "mocha-typescript";
import * as chai from "chai";
import * as chaiAsPromised from "chai-as-promised";
import { AesPmacSivExample } from "./support/test_vectors";

import WebCrypto = require("node-webcrypto-ossl");
import * as miscreant from "../src/index";

let expect = chai.expect;
chai.use(chaiAsPromised);

@suite class AesPmacSivSpec {
  static vectors: AesPmacSivExample[];

  static async before() {
    this.vectors = await AesPmacSivExample.loadAll();
  }

  @test async "should correctly seal and open with polyfill cipher implementations"() {
    const polyfillProvider = new miscreant.PolyfillCryptoProvider();

    for (let v of AesPmacSivSpec.vectors) {
      const siv = await miscreant.SIV.importKey(v.key, "AES-PMAC-SIV", polyfillProvider);
      const sealed = await siv.seal(v.plaintext, v.ad);
      expect(sealed).to.eql(v.ciphertext);

      const unsealed = await siv.open(sealed, v.ad, );
      expect(unsealed).not.to.be.null;
      expect(unsealed!).to.eql(v.plaintext);
      expect(() => siv.clear()).not.to.throw();
    }
  }

  @test async "should correctly seal and open with WebCrypto cipher implementations"() {
    const webCryptoProvider = new miscreant.WebCryptoProvider(new WebCrypto());

    for (let v of AesPmacSivSpec.vectors) {
      const siv = await miscreant.SIV.importKey(v.key, "AES-PMAC-SIV", webCryptoProvider);
      const sealed = await siv.seal(v.plaintext, v.ad);
      expect(sealed).to.eql(v.ciphertext);

      const unsealed = await siv.open(sealed, v.ad, );
      expect(unsealed).not.to.be.null;
      expect(unsealed!).to.eql(v.plaintext);
      expect(() => siv.clear()).not.to.throw();
    }
  }

  @test async "should not open with incorrect associated data"() {
    const polyfillProvider = new miscreant.PolyfillCryptoProvider();

    for (let v of AesPmacSivSpec.vectors) {
      const badAd = v.ad;
      badAd.push(new Uint8Array(1));

      const siv = await miscreant.SIV.importKey(v.key, "AES-PMAC-SIV", polyfillProvider);
      await expect(siv.open(v.ciphertext, badAd)).to.be.rejectedWith(miscreant.IntegrityError);
    }
  }

  @test async "should not open with incorrect ciphertext"() {
    const polyfillProvider = new miscreant.PolyfillCryptoProvider();

    for (let v of AesPmacSivSpec.vectors) {
      const badOutput = v.ciphertext;
      badOutput[0] ^= badOutput[0];
      badOutput[1] ^= badOutput[1];
      badOutput[3] ^= badOutput[8];

      const siv = await miscreant.SIV.importKey(v.key, "AES-PMAC-SIV", polyfillProvider);
      await expect(siv.open(badOutput, v.ad)).to.be.rejectedWith(miscreant.IntegrityError);
    }
  }
}
