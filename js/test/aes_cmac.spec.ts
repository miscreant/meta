// Copyright (C) 2016 Dmitry Chestnykh
// MIT License. See LICENSE file for details.

import { suite, test } from "mocha-typescript";
import { expect } from "chai";
import { AesCmacExample } from "./support/test_vectors";

import WebCrypto = require("node-webcrypto-ossl");
import PolyfillCryptoProvider from "../src/internal/polyfill/provider";
import WebCryptoProvider from "../src/internal/webcrypto/provider";
import Cmac from "../src/internal/mac/cmac";

@suite class PolyfillAesCmacSpec {
  static vectors: AesCmacExample[];

  static async before() {
    this.vectors = await AesCmacExample.loadAll();
  }

  @test async "passes the AES-CMAC test vectors"() {
    const polyfillProvider = new PolyfillCryptoProvider();

    for (let v of PolyfillAesCmacSpec.vectors) {
      const mac = await Cmac.importKey(polyfillProvider, v.key);
      await mac.update(v.message);
      expect(await mac.finish()).to.eql(v.tag);
    }
  }
}

@suite class WebCryptoAesCmacSpec {
  static vectors: AesCmacExample[];

  static async before() {
    this.vectors = await AesCmacExample.loadAll();
  }

  @test async "passes the AES-CMAC test vectors"() {
    const webCryptoProvider = new WebCryptoProvider(new WebCrypto());

    for (let v of PolyfillAesCmacSpec.vectors) {
      const mac = await Cmac.importKey(webCryptoProvider, v.key);
      await mac.update(v.message);
      expect(await mac.finish()).to.eql(v.tag);
    }
  }
}
