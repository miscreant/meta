// Copyright (C) 2016 Dmitry Chestnykh
// MIT License. See LICENSE file for details.

import { suite, test } from "mocha-typescript";
import { expect } from "chai";
import { AesCmacExample } from "./support/test_vectors";

import WebCrypto = require("node-webcrypto-ossl");

import PolyfillAes from "../src/internal/polyfill/aes";
import PolyfillAesCmac from "../src/internal/polyfill/aes_cmac";
import WebCryptoAesCmac from "../src/internal/webcrypto/aes_cmac";

@suite class PolyfillAesCmacSpec {
  static vectors: AesCmacExample[];

  static async before() {
    this.vectors = await AesCmacExample.loadAll();
  }

  @test async "passes the AES-CMAC test vectors"() {
    for (let v of PolyfillAesCmacSpec.vectors) {
      const mac = new PolyfillAesCmac(new PolyfillAes(v.key));
      await mac.update(v.input);
      expect(await mac.finish()).to.eql(v.result);
    }
  }
}

@suite class WebCryptoAesCmacSpec {
  static vectors: AesCmacExample[];

  static async before() {
    this.vectors = await AesCmacExample.loadAll();
  }

  @test async "passes the AES-CMAC test vectors"() {
    for (let v of PolyfillAesCmacSpec.vectors) {
      const mac = await WebCryptoAesCmac.importKey(v.key, new WebCrypto());
      await mac.update(v.input);
      expect(await mac.finish()).to.eql(v.result);
    }
  }
}
