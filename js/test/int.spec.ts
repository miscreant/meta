// Copyright (C) 2016 Dmitry Chestnykh
// MIT License. See LICENSE file for details.

import { suite, test } from "mocha-typescript";
import { expect } from "chai";
import { mul, add, sub } from "../src/int";

@suite class IntMulSpec {
  @test "should overflow"() {
    const float = 0xffffffff * 0x7fffffff;
    const int = mul(0xffffffff, 0x7fffffff);
    expect(int).to.be.lessThan(float);
  }

  @test "should return correct result"() {
    expect(mul(0x7fffffff, 0x5ffffff5)).to.eq(0x2000000b);
  }

  @test "should be commutative"() {
    expect(mul(0x7fffffff, 0x5ffffff5))
      .to.eq(mul(0x5ffffff5, 0x7fffffff));
  }
}

@suite class IntAddSpec {
  @test "should overflow"() {
    const float = 0xffffffff + 0x7fffffff;
    const int = add(0xffffffff, 0x7fffffff);
    expect(int).to.be.lessThan(float);
  }

  @test "should return correct result"() {
    expect(add(0xffffffff, 1)).to.eq(0);
    expect(add(2, 0xffffffff)).to.eq(1);
  }

  @test "should be commutative"() {
    expect(add(0x7fffffff, 0x5ffffff5))
      .to.eq(add(0x5ffffff5, 0x7fffffff));
  }
}

@suite class IntSub {
  @test "should overflow"() {
    const float = 0xffffffff + 0x7fffffff;
    const int = sub(0x7fffffff, 0xffffffff);
    expect(int).to.be.lessThan(float);
  }

  @test "should return correct result"() {
    expect(sub(1, 0xffffffff)).to.eq(2);
    expect(sub(2, 0xffffffff)).to.eq(3);
  }
}
