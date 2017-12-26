import { suite, test } from "mocha-typescript";
import { expect } from "chai";
import Block from "../src/internals/block";

import { DblExample } from "./support/test_vectors";

@suite class DblSpec {
  static vectors: DblExample[];

  static async before() {
    this.vectors = await DblExample.loadAll();
  }

  @test async "passes the AES-CMAC test vectors"() {
    let block = new Block();

    for (let v of DblSpec.vectors) {
      block.data.set(v.input);
      block.dbl();
      expect(block.data).to.eql(v.output);
    }
  }
}
