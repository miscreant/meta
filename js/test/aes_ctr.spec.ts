// Copyright (C) 2016 Dmitry Chestnykh
// MIT License. See LICENSE file for details.

import { suite, test } from "mocha-typescript";
import { expect } from "chai";
import { AesCtrExample } from "./support/test_vectors";

import WebCrypto = require("node-webcrypto-ossl");

import AesPolyfill from "../src/internal/polyfill/aes";
import AesCtrPolyfill from "../src/internal/polyfill/aes_ctr";
import AesCtrWebCrypto from "../src/internal/webcrypto/aes_ctr";

@suite class AesCtrSpec {
  static vectors: AesCtrExample[];

  static async before() {
    this.vectors = await AesCtrExample.loadAll();
  }

  @test async "passes test vectors using the AES-CTR polyfill"() {
    for (let v of AesCtrSpec.vectors) {
      const ctrPolyfill = new AesCtrPolyfill(new AesPolyfill(v.key));
      let ciphertext = await ctrPolyfill.encrypt(v.iv, v.src);
      expect(ciphertext).to.eql(v.dst);
    }
  }

  @test async "passes test vectors using the WebCrypto AES-CTR implementation"() {
    for (let v of AesCtrSpec.vectors) {
      const ctrNative = await AesCtrWebCrypto.importKey(v.key, new WebCrypto());
      let ciphertext = await ctrNative.encrypt(v.iv, v.src);
      expect(ciphertext).to.eql(v.dst);
    }
  }
}
