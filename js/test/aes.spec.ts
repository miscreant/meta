// Copyright (C) 2016-2017 Dmitry Chestnykh, Tony Arcieri
// MIT License. See LICENSE file for details.

import { suite, test } from "mocha-typescript";
import * as chai from "chai";
import * as chaiAsPromised from "chai-as-promised";
import { AesExample } from "./support/test_vectors";
import Block from "../src/internals/block";

import WebCrypto = require("node-webcrypto-ossl");
import WebCryptoAes from "../src/providers/webcrypto/aes";
import PolyfillAes from "../src/providers/polyfill/aes";

let expect = chai.expect;
chai.use(chaiAsPromised);

@suite class PolyfillAesSpec {
  static vectors: AesExample[];

  static async before() {
    this.vectors = await AesExample.loadAll();
  }

  @test "should not accept wrong key length"() {
    expect(() => new PolyfillAes(new Uint8Array(10))).to.throw(/invalid key length/);
  }

  @test "should correctly encrypt blocks"() {
    for (let v of PolyfillAesSpec.vectors) {
      const cipher = new PolyfillAes(v.key);
      const block = new Block();
      block.data.set(v.src);
      cipher.encryptBlock(block);
      expect(block.data).to.eql(v.dst);
    }
  }

  @test "should correctly encrypt many blocks with different keys"() {
    let key = new Uint8Array(32);
    let block = new Block();
    const newKey = new Uint8Array(32);
    for (let i = 0; i < 100; i++) {
      const cipher = new PolyfillAes(key);
      for (let j = 0; j < 100; j++) {
        cipher.encryptBlock(block);
      }
      newKey.set(key.subarray(16, 32)); // move 16 bytes to left
      newKey.set(block.data, 16); // fill the rest 16 bytes with block
      key.set(newKey);
    }

    let expected = new Uint8Array([58, 111, 217, 50, 246, 8, 131, 95, 31, 86, 217, 220, 31, 206, 207, 163]);
    expect(block.data).to.eql(expected);
  }
}

@suite class WebCryptoAesSpec {
  static vectors: AesExample[];

  static async before() {
    this.vectors = await AesExample.loadAll();
  }

  @test "should not accept wrong key length"() {
    const crypto = new WebCrypto();
    expect(WebCryptoAes.importKey(crypto, new Uint8Array(10))).to.be.rejectedWith(Error);
  }

  @test async "should correctly encrypt blocks"() {
    const crypto = new WebCrypto();

    for (let v of WebCryptoAesSpec.vectors) {
      const cipher = await WebCryptoAes.importKey(crypto, v.key);
      const block = new Block();
      block.data.set(v.src);
      await cipher.encryptBlock(block);
      expect(block.data).to.eql(v.dst);
    }
  }
}
