// Copyright (C) 2016-2017 Dmitry Chestnykh, Tony Arcieri
// MIT License. See LICENSE file for details.

import { suite, test } from "mocha-typescript";
import { expect } from "chai";
import { AesPmacExample } from "./support/test_vectors";

import WebCrypto = require("node-webcrypto-ossl");
import * as miscreant from "../src/index";


@suite class PolyfillAesPmacSpec {
  static vectors: AesPmacExample[];

  static async before() {
    this.vectors = await AesPmacExample.loadAll();
  }

  @test async "passes the AES-PMAC test vectors"() {
    const polyfillProvider = new miscreant.PolyfillCryptoProvider();

    for (let v of PolyfillAesPmacSpec.vectors) {
      const mac = await miscreant.PMAC.importKey(polyfillProvider, v.key);
      await mac.update(v.message);
      expect(v.tag).to.eql(await mac.finish());
    }
  }
}

@suite class WebCryptoAesPmacSpec {
  static vectors: AesPmacExample[];

  static async before() {
    this.vectors = await AesPmacExample.loadAll();
  }

  @test async "passes the AES-PMAC test vectors"() {
    const webCryptoProvider = new miscreant.WebCryptoProvider(new WebCrypto());

    for (let v of PolyfillAesPmacSpec.vectors) {
      const mac = await miscreant.PMAC.importKey(webCryptoProvider, v.key);
      await mac.update(v.message);
      expect(v.tag).to.eql(await mac.finish());
    }
  }
}
