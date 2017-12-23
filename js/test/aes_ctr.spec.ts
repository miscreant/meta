// Copyright (C) 2016 Dmitry Chestnykh
// MIT License. See LICENSE file for details.

import { suite, test } from "mocha-typescript";
import { expect } from "chai";
import { AesCtrExample } from "./support/test_vectors";

import WebCrypto = require("node-webcrypto-ossl");

import PolyfillAes from "../src/providers/polyfill/aes";
import PolyfillAesCtr from "../src/providers/polyfill/aes_ctr";
import WebCryptoAesCtr from "../src/providers/webcrypto/aes_ctr";

@suite class PolyfillAesCtrSpec {
  static vectors: AesCtrExample[];

  static async before() {
    this.vectors = await AesCtrExample.loadAll();
  }

  @test async "passes the AES-CTR test vectors"() {
    for (let v of PolyfillAesCtrSpec.vectors) {
      const ctrPolyfill = new PolyfillAesCtr(new PolyfillAes(v.key));
      let ciphertext = await ctrPolyfill.encryptCtr(v.iv, v.plaintext);
      expect(ciphertext).to.eql(v.ciphertext);
    }
  }
}

@suite class WebCryptoAesCtrSpec {
  static vectors: AesCtrExample[];

  static async before() {
    this.vectors = await AesCtrExample.loadAll();
  }

  @test async "passes the AES-CTR test vectors"() {
    for (let v of WebCryptoAesCtrSpec.vectors) {
      const ctrNative = await WebCryptoAesCtr.importKey(new WebCrypto(), v.key);
      let ciphertext = await ctrNative.encryptCtr(v.iv, v.plaintext);
      expect(ciphertext).to.eql(v.ciphertext);
    }
  }
}
