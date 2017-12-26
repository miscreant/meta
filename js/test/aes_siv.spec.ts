// Copyright (C) 2017 Dmitry Chestnykh
// MIT License. See LICENSE file for details.

import { suite, test } from "mocha-typescript";
import * as chai from "chai";
import * as chaiAsPromised from "chai-as-promised";
import { AesSivExample } from "./support/test_vectors";

import WebCrypto = require("node-webcrypto-ossl");
import * as miscreant from "../src/index";

let expect = chai.expect;
chai.use(chaiAsPromised);

@suite class AesSivSpec {
  static vectors: AesSivExample[];

  static async before() {
    this.vectors = await AesSivExample.loadAll();
  }

  @test async "should correctly seal and open with polyfill cipher implementations"() {
    const polyfillProvider = new miscreant.PolyfillCryptoProvider();

    for (let v of AesSivSpec.vectors) {
      const siv = await miscreant.SIV.importKey(v.key, "AES-SIV", polyfillProvider);
      const sealed = await siv.seal(v.plaintext, v.ad);
      expect(sealed).to.eql(v.ciphertext);

      const unsealed = await siv.open(sealed, v.ad);
      expect(unsealed).not.to.be.null;
      expect(unsealed!).to.eql(v.plaintext);
      expect(() => siv.clear()).not.to.throw();
    }
  }

  @test async "should correctly seal and open with WebCrypto cipher implementations"() {
    const webCryptoProvider = new miscreant.WebCryptoProvider(new WebCrypto());

    for (let v of AesSivSpec.vectors) {
      const siv = await miscreant.SIV.importKey(v.key, "AES-SIV", webCryptoProvider);
      const sealed = await siv.seal(v.plaintext, v.ad);
      expect(sealed).to.eql(v.ciphertext);

      const unsealed = await siv.open(sealed, v.ad);
      expect(unsealed).not.to.be.null;
      expect(unsealed!).to.eql(v.plaintext);
      expect(() => siv.clear()).not.to.throw();
    }
  }

  @test async "should correctly seal and open different plaintext under the same key"() {
    const polyfillProvider = new miscreant.PolyfillCryptoProvider();

    const key = byteSeq(64);
    const ad1 = [byteSeq(32), byteSeq(10)];
    const pt1 = byteSeq(100);

    const ad2 = [byteSeq(32), byteSeq(10)];
    const pt2 = byteSeq(40, 100);

    const siv = await miscreant.SIV.importKey(key, "AES-SIV", polyfillProvider);

    const sealed1 = await siv.seal(pt1, ad1);
    const opened1 = await siv.open(sealed1, ad1);
    expect(opened1).not.to.be.null;
    expect(opened1!).to.eql(pt1);

    const sealed2 = await siv.seal(pt2, ad2);
    const opened2 = await siv.open(sealed2, ad2);
    expect(opened2).not.to.be.null;
    expect(opened2!).to.eql(pt2);

    expect(() => siv.clear()).not.to.throw();
  }

  @test async "should not open with incorrect key"() {
    const polyfillProvider = new miscreant.PolyfillCryptoProvider();

    for (let v of AesSivSpec.vectors) {
      const badKey = v.key;
      badKey[0] ^= badKey[0];
      badKey[2] ^= badKey[2];
      badKey[3] ^= badKey[8];

      const siv = await miscreant.SIV.importKey(badKey, "AES-SIV", polyfillProvider);
      await expect(siv.open(v.ciphertext, v.ad)).to.be.rejectedWith(miscreant.IntegrityError);
    }
  }

  @test async "should not open with incorrect associated data"() {
    const polyfillProvider = new miscreant.PolyfillCryptoProvider();

    for (let v of AesSivSpec.vectors) {
      const badAd = v.ad;
      badAd.push(new Uint8Array(1));

      const siv = await miscreant.SIV.importKey(v.key, "AES-SIV", polyfillProvider);
      await expect(siv.open(v.ciphertext, badAd)).to.be.rejectedWith(miscreant.IntegrityError);
    }
  }

  @test async "should not open with incorrect ciphertext"() {
    const polyfillProvider = new miscreant.PolyfillCryptoProvider();

    for (let v of AesSivSpec.vectors) {
      const badOutput = v.ciphertext;
      badOutput[0] ^= badOutput[0];
      badOutput[1] ^= badOutput[1];
      badOutput[3] ^= badOutput[8];

      const siv = await miscreant.SIV.importKey(v.key, "AES-SIV", polyfillProvider);
      await expect(siv.open(badOutput, v.ad)).to.be.rejectedWith(miscreant.IntegrityError);
    }
  }
}

/**
 * Returns a Uint8Array of the given length containing
 * sequence of bytes 0, 1, 2 ... 255, 0, 1, 2, ...
 *
 * If the start byte is given, the sequence starts from it.
 */
function byteSeq(length: number, start = 0): Uint8Array {
  const b = new Uint8Array(length);
  for (let i = 0; i < b.length; i++) {
    b[i] = (start + i) & 0xff;
  }
  return b;
}
