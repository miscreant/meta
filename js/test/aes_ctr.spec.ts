// Copyright (C) 2016 Dmitry Chestnykh
// MIT License. See LICENSE file for details.

import { suite, test } from "mocha-typescript";
import { expect } from "chai";
import { AesPolyfill } from "../src/internal/polyfill/aes";
import { AesCtrPolyfill } from "../src/internal/polyfill/aes_ctr";
import { AesCtrExample } from "./support/test_vectors";

@suite class AesCtrSpec {
  static vectors: AesCtrExample[];

  static async before() {
    this.vectors = await AesCtrExample.loadAll();
  }

  @test async "should correctly encrypt"() {
    for (let v of AesCtrSpec.vectors) {
      // TODO: automated tests for WebCrypto AES-CTR
      const ctrPolyfill = new AesCtrPolyfill(new AesPolyfill(v.key));
      let ciphertext = await ctrPolyfill.encrypt(v.iv, v.src);
      expect(ciphertext).to.eql(v.dst);
    }
  }
}
