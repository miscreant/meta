// Copyright (C) 2017 Dmitry Chestnykh
// MIT License. See LICENSE file for details.

import { suite, test } from "mocha-typescript";
import { expect } from "chai";
import { AesSivExample } from "./support/test_vectors";

import WebCrypto = require("node-webcrypto-ossl");

import Miscreant from "../src/miscreant";

@suite class SivSpec {
  static vectors: AesSivExample[];

  static async before() {
    this.vectors = await AesSivExample.loadAll();
  }

  @test async "AES-SIV: should correctly seal and open with WebCrypto"() {
    for (let v of SivSpec.vectors) {
      const siv = await Miscreant.importKey(v.key, "AES-SIV", new WebCrypto());
      const sealed = await siv.seal(v.plaintext, v.ad);
      expect(sealed).to.eql(v.ciphertext);

      const unsealed = await siv.open(sealed, v.ad);
      expect(unsealed).not.to.be.null;
      expect(unsealed!).to.eql(v.plaintext);
      expect(() => siv.clear()).not.to.throw();
    }
  }

  @test async "AES-SIV: should correctly seal and open with PolyfillCrypto"() {
    for (let v of SivSpec.vectors) {
      const siv = await Miscreant.importKey(v.key, "AES-SIV", Miscreant.getCryptoProvider("polyfill"));
      const sealed = await siv.seal(v.plaintext, v.ad);
      expect(sealed).to.eql(v.ciphertext);

      const unsealed = await siv.open(sealed, v.ad);
      expect(unsealed).not.to.be.null;
      expect(unsealed!).to.eql(v.plaintext);
      expect(() => siv.clear()).not.to.throw();
    }
  }
}
