// Copyright (C) 2016 Dmitry Chestnykh
// MIT License. See LICENSE file for details.

import { suite, test } from "mocha-typescript";
import { expect } from "chai";
import { select, compare, equal } from "../src/internals/constant-time";

@suite class SelectSpec {
  @test "should select correct value"() {
    expect(select(1, 2, 3)).to.eq(2);
    expect(select(1, 3, 2)).to.eq(3);
    expect(select(0, 2, 3)).to.eq(3);
    expect(select(0, 3, 2)).to.eq(2);
  }
}

@suite class compareSpec {
  static readonly a = new Uint8Array([1, 2, 3, 4]);
  static readonly b = new Uint8Array([1, 2, 3, 4]);
  static readonly c = new Uint8Array([1, 2, 5, 4]);
  static readonly d = new Uint8Array([1, 2, 3]);
  static readonly z = new Uint8Array(0);

  @test "should return 0 if inputs have different lenghts"() {
    expect(compare(compareSpec.a, compareSpec.d)).to.eq(0);
  }

  @test "should return 1 if inputs are equal"() {
    expect(compare(compareSpec.a, compareSpec.b)).to.eq(1);
  }

  @test "should return 0 if inputs are not equal"() {
    expect(compare(compareSpec.a, compareSpec.c)).to.eq(0);
  }

  @test "should return 1 if given zero-length inputs "() {
    expect(compare(compareSpec.z, compareSpec.z)).to.eq(1);
  }
}

@suite class EqualSpec {
  static readonly a = new Uint8Array([1, 2, 3, 4]);
  static readonly b = new Uint8Array([1, 2, 3, 4]);
  static readonly c = new Uint8Array([1, 2, 5, 4]);
  static readonly d = new Uint8Array([1, 2, 3]);
  static readonly z = new Uint8Array(0);

  @test "should return false if inputs have different lenghts"() {
    expect(equal(EqualSpec.a, EqualSpec.d)).to.eq(false);
  }

  @test "should return true if inputs are equal"() {
    expect(equal(EqualSpec.a, EqualSpec.b)).to.eq(true);
  }

  @test "should return false if inputs are not equal"() {
    expect(equal(EqualSpec.a, EqualSpec.c)).to.eq(false);
  }

  @test "should return false if given zero-length inputs "() {
    expect(equal(EqualSpec.z, EqualSpec.z)).to.eq(false);
  }

}
