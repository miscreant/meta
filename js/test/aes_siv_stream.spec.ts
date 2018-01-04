import { suite, test } from "mocha-typescript";
import * as chai from "chai";
import * as chaiAsPromised from "chai-as-promised";
import { STREAMExample } from "./support/test_vectors";

import WebCrypto = require("node-webcrypto-ossl");
import * as miscreant from "../src/index";

let expect = chai.expect;
chai.use(chaiAsPromised);

@suite class STREAMSpec {
  static vectors: STREAMExample[];

  static async before() {
    this.vectors = await STREAMExample.loadAll();
  }

  @test async "should correctly seal and open with polyfill cipher implementations"() {
    const polyfillProvider = new miscreant.PolyfillCryptoProvider();

    for (let v of STREAMSpec.vectors) {
      const encryptor = await miscreant.StreamEncryptor.importKey(v.key, v.nonce, v.alg, polyfillProvider);
      const decryptor = await miscreant.StreamDecryptor.importKey(v.key, v.nonce, v.alg, polyfillProvider);

      for (var [i, b] of v.blocks.entries()) {
        const lastBlock = (i + 1 >= v.blocks.length);

        const sealed = await encryptor.seal(b.plaintext, lastBlock, b.ad);
        expect(sealed).to.eql(b.ciphertext);

        const unsealed = await decryptor.open(sealed, lastBlock, b.ad);
        expect(unsealed).not.to.be.null;
        expect(unsealed!).to.eql(b.plaintext);
      }

      expect(() => encryptor.clear()).not.to.throw();
      expect(() => decryptor.clear()).not.to.throw();
    }
  }

  @test async "should correctly seal and open with WebCrypto cipher implementations"() {
    const webCryptoProvider = new miscreant.WebCryptoProvider(new WebCrypto());

    for (let v of STREAMSpec.vectors) {
      const encryptor = await miscreant.StreamEncryptor.importKey(v.key, v.nonce, v.alg, webCryptoProvider);
      const decryptor = await miscreant.StreamDecryptor.importKey(v.key, v.nonce, v.alg, webCryptoProvider);

      for (var [i, b] of v.blocks.entries()) {
        const lastBlock = (i + 1 >= v.blocks.length);

        const sealed = await encryptor.seal(b.plaintext, lastBlock, b.ad);
        expect(sealed).to.eql(b.ciphertext);

        const unsealed = await decryptor.open(sealed, lastBlock, b.ad);
        expect(unsealed).not.to.be.null;
        expect(unsealed!).to.eql(b.plaintext);
      }

      expect(() => encryptor.clear()).not.to.throw();
      expect(() => decryptor.clear()).not.to.throw();
    }
  }

  @test async "should not open with incorrect key"() {
    const polyfillProvider = new miscreant.PolyfillCryptoProvider();

    for (let v of STREAMSpec.vectors) {
      const badKey = v.key;
      badKey[0] ^= badKey[0];
      badKey[2] ^= badKey[2];
      badKey[3] ^= badKey[8];

      const decryptor = await miscreant.StreamDecryptor.importKey(badKey, v.nonce, v.alg, polyfillProvider);

      for (var [i, b] of v.blocks.entries()) {
        const lastBlock = (i + 1 >= v.blocks.length);
        await expect(decryptor.open(b.ciphertext, lastBlock, b.ad)).to.be.rejectedWith(miscreant.IntegrityError);
      }
    }
  }

  @test async "should not open with incorrect associated data"() {
    const polyfillProvider = new miscreant.PolyfillCryptoProvider();

    for (let v of STREAMSpec.vectors) {
      const decryptor = await miscreant.StreamDecryptor.importKey(v.key, v.nonce, v.alg, polyfillProvider);
      const badAd = new Uint8Array(1);

      for (var [i, b] of v.blocks.entries()) {
        const lastBlock = (i + 1 >= v.blocks.length);
        await expect(decryptor.open(b.ciphertext, lastBlock, badAd)).to.be.rejectedWith(miscreant.IntegrityError);
      }
    }
  }

  @test async "should not open with incorrect ciphertext"() {
    const polyfillProvider = new miscreant.PolyfillCryptoProvider();

    for (let v of STREAMSpec.vectors) {
      const decryptor = await miscreant.StreamDecryptor.importKey(v.key, v.nonce, v.alg, polyfillProvider);

      for (var [i, b] of v.blocks.entries()) {
        const lastBlock = (i + 1 >= v.blocks.length);

        const badOutput = b.ciphertext;
        badOutput[0] ^= badOutput[0];
        badOutput[1] ^= badOutput[1];
        badOutput[3] ^= badOutput[8];

        await expect(decryptor.open(badOutput, lastBlock, b.ad)).to.be.rejectedWith(miscreant.IntegrityError);
      }
    }
  }
}
