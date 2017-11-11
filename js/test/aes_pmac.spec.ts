// Copyright (C) 2016-2017 Dmitry Chestnykh, Tony Arcieri
// MIT License. See LICENSE file for details.

import { suite, test } from "mocha-typescript";
import { expect } from "chai";
import { AesPmacExample } from "./support/test_vectors";

import WebCrypto = require("node-webcrypto-ossl");
import PolyfillCryptoProvider from "../src/internal/polyfill/provider";
import WebCryptoProvider from "../src/internal/webcrypto/provider";
import Pmac from "../src/internal/mac/pmac";

@suite
class PolyfillAesPmacSpec {
  static vectors: AesPmacExample[];

  static async before() {
    this.vectors = await AesPmacExample.loadAll();
  }

  @test
  async "passes the AES-PMAC test vectors"() {
    const polyfillProvider = new PolyfillCryptoProvider();

    for (let v of PolyfillAesPmacSpec.vectors) {
      const mac = await Pmac.importKey(polyfillProvider, v.key);
      await mac.update(v.message);
      expect(v.tag).to.eql(await mac.finish());
    }
  }
}

@suite
class WebCryptoAesPmacSpec {
  static vectors: AesPmacExample[];

  static async before() {
    this.vectors = await AesPmacExample.loadAll();
  }

  @test
  async "passes the AES-PMAC test vectors"() {
    const webCryptoProvider = new WebCryptoProvider(new WebCrypto());

    for (let v of PolyfillAesPmacSpec.vectors) {
      const mac = await Pmac.importKey(webCryptoProvider, v.key);
      await mac.update(v.message);
      expect(v.tag).to.eql(await mac.finish());
    }
  }
}
