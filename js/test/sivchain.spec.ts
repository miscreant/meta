// Copyright (C) 2017 Dmitry Chestnykh
// MIT License. See LICENSE file for details.

import { suite, test } from "mocha-typescript";
import * as chai from "chai";
import * as chaiAsPromised from "chai-as-promised";
import { AESSIV, IntegrityError } from "../src/sivchain";
import { encode, decode } from "../src/internal/hex";

let expect = chai.expect;
chai.use(chaiAsPromised);

// tslint:disable
const vectors = [
  // A.1.  Deterministic Authenticated Encryption Example
  {
    key: "fffefdfc fbfaf9f8 f7f6f5f4 f3f2f1f0 f0f1f2f3 f4f5f6f7 f8f9fafb fcfdfeff",
    ad: ["10111213 14151617 18191a1b 1c1d1e1f 20212223 24252627"],
    plaintext: "11223344 55667788 99aabbcc ddee",
    output: "85632d07 c6e8f37f 950acd32 0a2ecc93 40c02b96 90c4dc04 daef7f6a fe5c",
  },
  //A.2.  Nonce-Based Authenticated Encryption Example
  {
    key: "7f7e7d7c 7b7a7978 77767574 73727170 40414243 44454647 48494a4b 4c4d4e4f",
    ad: [
      "00112233 44556677 8899aabb ccddeeff deaddada deaddada ffeeddcc bbaa9988 77665544 33221100", //AD1
      "10203040 50607080 90a0",                                                                    //AD2
      "09f91102 9d74e35b d84156c5 635688c0",                                                       // nonce
    ],
    plaintext: "74686973 20697320 736f6d65 20706c61 696e7465 78742074 6f20656e 63727970 74207573 696e6720 5349562d 414553",
    output: "7bdb6e3b 432667eb 06f4d14b ff2fbd0f cb900f2f ddbe4043 26601965 c889bf17 dba77ceb 094fa663 b7a3f748 ba8af829 ea64ad54 4a272e9c 485b62a3 fd5c0d",
  },
  {
    key: "fffefdfc fbfaf9f8 f7f6f5f4 f3f2f1f0 f0f1f2f3 f4f5f6f7 f8f9fafb fcfdfeff",
    ad: [],
    plaintext: "",
    output: "f2007a5beb2b8900c588a7adf599f172",
  },
  // http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/siv/siv-test-vectors.txt
  // TEST CASE #1
  // 192 bit subkeys
  {
    key: "fffefdfc fbfaf9f8 f7f6f5f4 f3f2f1f0 6f6e6d6c 6b6a6968 f0f1f2f3 f4f5f6f7 f8f9fafb fcfdfeff 00010203 04050607",
    ad: ["10111213 14151617 18191a1b 1c1d1e1f 20212223 24252627"],
    plaintext: "11223344 55667788 99aabbcc ddee",
    output: "02347811 daa8b274 91f24448 932775a6 2af34a06 ac0016e8 ac284a55 14f6",
  },
  // 256 bit subkeys
  {
    key: "fffefdfc fbfaf9f8 f7f6f5f4 f3f2f1f0 6f6e6d6c 6b6a6968 67666564 63626160 f0f1f2f3 f4f5f6f7 f8f9fafb fcfdfeff 00010203 04050607 08090a0b 0c0d0e0f",
    ad: ["10111213 14151617 18191a1b 1c1d1e1f 20212223 24252627"],
    plaintext: "11223344 55667788 99aabbcc ddee",
    output: "f125274c 598065cf c26b0e71 57502908 8b035217 e380cac8 919ee800 c126",
  },
  // TEST CASE #2
  // 192 bit subkeys
  {
    key: "7f7e7d7c 7b7a7978 77767574 73727170 6f6e6d6c 6b6a6968 40414243 44454647 48494a4b 4c4d4e4f 50515253 54555657",
    ad: [
      "00112233 44556677 8899aabb ccddeeff deaddada deaddada ffeeddcc bbaa9988 77665544 33221100",
      "10203040 50607080 90a0",
      "09f91102 9d74e35b d84156c5 635688c0",
    ],
    plaintext: "74686973 20697320 736f6d65 20706c61 696e7465 78742074 6f20656e 63727970 74207573 696e6720 5349562d 414553",
    output: "de40aa1e 7180d519 cb14308e a7f77586 da09877c 510f2965 1f42311a b728e956 09e7de29 94bdf80b b99bfaac e31c4ec0 d15ba650 9f53f36a d725dcab c9e2a7",
  },
  // 256 bit subkeys
  {
    key: "7f7e7d7c 7b7a7978 77767574 73727170 6f6e6d6c 6b6a6968 67666564 63626160 40414243 44454647 48494a4b 4c4d4e4f 50515253 54555657 58595a5b 5b5d5e5f",
    ad: [
      "00112233 44556677 8899aabb ccddeeff deaddada deaddada ffeeddcc bbaa9988 77665544 33221100",
      "10203040 50607080 90a0",
      "09f91102 9d74e35b d84156c5 635688c0",
    ],
    plaintext: "74686973 20697320 736f6d65 20706c61 696e7465 78742074 6f20656e 63727970 74207573 696e6720 5349562d 414553",
    output: "85b81673 10038db7 dc4692c0 281ca358 68181b27 62f3c24f 2efa5fb8 0cb14351 6ce6c434 b898a6fd 8eb98a41 8842f51f 66fc67de 43ac185a 66dd7247 5bbb08",
  }
];
// tslint:enable

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

function dec(s: string): Uint8Array {
  return decode(s.replace(/ /g, ""));
}

@suite class SIVSpec {
  @test async "should correctly seal and open"() {
    for (let v of vectors) {
      const key = dec(v.key);
      const ad = v.ad.map(dec);
      const plaintext = dec(v.plaintext);
      const output = dec(v.output);

      const siv = await AESSIV.importKey(key);
      const sealed = await siv.seal(ad, plaintext);
      expect(encode(sealed)).to.eql(encode(output));
      const unsealed = await siv.open(ad, sealed);
      expect(unsealed).not.to.be.null;
      expect(encode(unsealed!)).to.eql(encode(plaintext));
      expect(() => siv.clean()).not.to.throw();
    }
  }

  @test async "should correctly seal and open different plaintext under the same key"() {
    const key = byteSeq(64);
    const ad1 = [byteSeq(32), byteSeq(10)];
    const pt1 = byteSeq(100);

    const ad2 = [byteSeq(32), byteSeq(10)];
    const pt2 = byteSeq(40, 100);

    const siv = await AESSIV.importKey(key);

    const sealed1 = await siv.seal(ad1, pt1);
    const opened1 = await siv.open(ad1, sealed1);
    expect(opened1).not.to.be.null;
    expect(encode(opened1!)).to.eql(encode(pt1));

    const sealed2 = await siv.seal(ad2, pt2);
    const opened2 = await siv.open(ad2, sealed2);
    expect(opened2).not.to.be.null;
    expect(encode(opened2!)).to.eql(encode(pt2));

    expect(() => siv.clean()).not.to.throw();
  }

  @test async "should not open with incorrect key"() {
    for (let v of vectors) {
      const badKey = dec(v.key);
      badKey[0] ^= badKey[0];
      badKey[2] ^= badKey[2];
      badKey[3] ^= badKey[8];
      const ad = v.ad.map(dec);
      const output = dec(v.output);

      const siv = await AESSIV.importKey(badKey);
      expect(siv.open(ad, output)).to.be.rejectedWith(IntegrityError);
    }
  }

  @test async "should not open with incorrect associated data"() {
    for (let v of vectors) {
      const key = dec(v.key);
      const badAd = v.ad.map(dec);
      badAd.push(new Uint8Array(1));
      const output = dec(v.output);

      const siv = await AESSIV.importKey(key);
      return expect(siv.open(badAd, output)).to.be.rejectedWith(IntegrityError);
    }
  }

  @test async "should not open with incorrect ciphertext"() {
    for (let v of vectors) {
      const key = dec(v.key);
      const ad = v.ad.map(dec);
      const badOutput = dec(v.output);
      badOutput[0] ^= badOutput[0];
      badOutput[1] ^= badOutput[1];
      badOutput[3] ^= badOutput[8];

      const siv = await AESSIV.importKey(key);
      return expect(siv.open(ad, badOutput)).to.be.rejectedWith(IntegrityError);
    }
  }
}

