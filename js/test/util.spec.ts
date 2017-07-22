import { suite, test } from "mocha-typescript";
import { expect } from "chai";
import { dbl, wipe } from "../src/internal/util";

import { DblExample } from "./support/test_vectors";

@suite class DblSpec {
  static vectors: DblExample[];

  static async before() {
    this.vectors = await DblExample.loadAll();
  }

  @test async "passes the AES-CMAC test vectors"() {
    let result = new Uint8Array(16);

    for (let v of DblSpec.vectors) {
      dbl(v.input, result);
      expect(result).to.eql(v.output);
    }
  }
}

@suite class WipeSpec {
  @test "should wipe bytes"() {
    const a = new Uint8Array([1, 2, 3, 4]);
    wipe(a);
    expect(a).to.eql(new Uint8Array(4));
  }
}
