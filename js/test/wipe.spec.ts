import { suite, test } from "mocha-typescript";
import { expect } from "chai";
import { wipe } from "../src/internals/wipe";

@suite class WipeSpec {
  @test "should wipe bytes"() {
    const a = new Uint8Array([1, 2, 3, 4]);
    wipe(a);
    expect(a).to.eql(new Uint8Array(4));
  }
}
