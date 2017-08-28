// Copyright (C) 2017 Dmitry Chestnykh
// MIT License. See LICENSE file for details.

import { suite, test } from "mocha-typescript";
import { expect } from "chai";
import { AesSivExample, AesPmacSivExample } from "./support/test_vectors";
import WebCryptoProvider from "../src/internal/webcrypto/provider";

import WebCrypto = require("node-webcrypto-ossl");

import Miscreant from "../src/miscreant";

@suite class MiscreantAesSivSpec {
  static vectors: AesSivExample[];

  static async before() {
    this.vectors = await AesSivExample.loadAll();
  }

  @test async "AES-SIV: should correctly seal and open with PolyfillCrypto"() {
    const polyfillProvider = Miscreant.polyfillCryptoProvider();
    for (let v of MiscreantAesSivSpec.vectors) {
      const siv = await Miscreant.importKey(v.key, "AES-SIV", polyfillProvider);
      const sealed = await siv.seal(v.plaintext, v.ad);
      expect(sealed).to.eql(v.ciphertext);

      const unsealed = await siv.open(sealed, v.ad);
      expect(unsealed).not.to.be.null;
      expect(unsealed!).to.eql(v.plaintext);
      expect(() => siv.clear()).not.to.throw();
    }
  }

  @test async "AES-SIV: should correctly seal and open with WebCrypto"() {
    const webCryptoProvider = new WebCryptoProvider(new WebCrypto());

    for (let v of MiscreantAesSivSpec.vectors) {
      const siv = await Miscreant.importKey(v.key, "AES-SIV", webCryptoProvider);
      const sealed = await siv.seal(v.plaintext, v.ad);
      expect(sealed).to.eql(v.ciphertext);

      const unsealed = await siv.open(sealed, v.ad);
      expect(unsealed).not.to.be.null;
      expect(unsealed!).to.eql(v.plaintext);
      expect(() => siv.clear()).not.to.throw();
    }
  }
}

@suite class MiscreantAesPmacSivSpec {
  static vectors: AesPmacSivExample[];

  static async before() {
    this.vectors = await AesPmacSivExample.loadAll();
  }

  @test async "AES-PMAC-SIV: should correctly seal and open with PolyfillCrypto"() {
    const polyfillProvider = Miscreant.polyfillCryptoProvider();
    for (let v of MiscreantAesPmacSivSpec.vectors) {
      const siv = await Miscreant.importKey(v.key, "AES-PMAC-SIV", polyfillProvider);
      const sealed = await siv.seal(v.plaintext, v.ad);
      expect(sealed).to.eql(v.ciphertext);

      const unsealed = await siv.open(sealed, v.ad);
      expect(unsealed).not.to.be.null;
      expect(unsealed!).to.eql(v.plaintext);
      expect(() => siv.clear()).not.to.throw();
    }
  }

  @test async "AES-PMAC-SIV: should correctly seal and open with WebCrypto"() {
    const webCryptoProvider = new WebCryptoProvider(new WebCrypto());

    for (let v of MiscreantAesPmacSivSpec.vectors) {
      const siv = await Miscreant.importKey(v.key, "AES-PMAC-SIV", webCryptoProvider);
      const sealed = await siv.seal(v.plaintext, v.ad);
      expect(sealed).to.eql(v.ciphertext);

      const unsealed = await siv.open(sealed, v.ad);
      expect(unsealed).not.to.be.null;
      expect(unsealed!).to.eql(v.plaintext);
      expect(() => siv.clear()).not.to.throw();
    }
  }
}
