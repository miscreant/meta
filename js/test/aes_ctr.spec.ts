// Copyright (C) 2016 Dmitry Chestnykh
// MIT License. See LICENSE file for details.

import { suite, test } from "mocha-typescript";
import { expect } from "chai";
import { AES } from "../src/internal/polyfill/aes";
import { CTR } from "../src/internal/polyfill/ctr";
import { AesCtrExample } from "./support/test_vectors";

@suite class AesCtrSpec {
  static vectors: AesCtrExample[];

  static async before() {
    this.vectors = await AesCtrExample.loadAll();
  }

  @test "should correctly encrypt"() {
    for (let v of AesCtrSpec.vectors) {
      const cipher = new AES(v.key);
      const ctr = new CTR(cipher, v.iv);

      for (let chunk in v.src) {
        const dst = new Uint8Array(v.dst[chunk].length);
        ctr.streamXOR(v.src[chunk], dst);
        expect(dst).to.eql(v.dst[chunk]);
      }
    }
  }

  @test "should generate succession when calling multiple times"() {
    for (let v of AesCtrSpec.vectors) {
      const cipher = new AES(v.key);

      const dst1 = new Uint8Array(100);
      const dst2 = new Uint8Array(dst1.length);

      // full-length
      const ctr1 = new CTR(cipher, v.iv);
      ctr1.stream(dst1);

      // partial
      const ctr2 = new CTR(cipher, v.iv);

      ctr2.stream(dst2.subarray(0, 50));
      ctr2.stream(dst2.subarray(50));

      expect(dst2).to.eql(dst1);
    }
  }
}
