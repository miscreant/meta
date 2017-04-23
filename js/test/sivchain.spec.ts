import { suite, test } from "mocha-typescript";
import { expect } from "chai";

@suite class SIVChainSpec {
  @test "true is still true"() {
    expect(true).to.eq(true);
  }
}
