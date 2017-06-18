// Copyright (C) 2016 Dmitry Chestnykh
// MIT License. See LICENSE file for details.

import { suite, test } from "mocha-typescript";
import { expect } from "chai";
import { AesCmacPolyfill } from "../src/internal/polyfill/aes_cmac";
import { AesPolyfill } from "../src/internal/polyfill/aes";
import { AesCmacExample } from "./support/test_vectors";

@suite class AesCmacSpec {
  static vectors: AesCmacExample[];

  static async before() {
    this.vectors = await AesCmacExample.loadAll();
  }

  @test "should produce correct results for test vectors"() {
    for (let v of AesCmacSpec.vectors) {
      const mac = new AesCmacPolyfill(new AesPolyfill(v.key));
      mac.update(v.input);
      expect(mac.digest()).to.eql(v.result);
    }
  }
}
