// Copyright (C) 2016 Dmitry Chestnykh
// MIT License. See LICENSE file for details.

import { AES } from "./aes";
import { encode, decode } from "@stablelib/hex";

// TODO(dchest): add more AES test vectors.
const testVectors = [
    {
        key: "2B7E151628AED2A6ABF7158809CF4F3C",
        src: "3243F6A8885A308D313198A2E0370734",
        dst: "3925841D02DC09FBDC118597196A0B32"
    },
    {
        key: "000102030405060708090A0B0C0D0E0F",
        src: "00112233445566778899AABBCCDDEEFF",
        dst: "69C4E0D86A7B0430D8CDB78070B4C55A"
    },
    {
        key: "000102030405060708090A0B0C0D0E0F1011121314151617",
        src: "00112233445566778899AABBCCDDEEFF",
        dst: "DDA97CA4864CDFE06EAF70A0EC0D7191"
    },
    {
        key: "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
        src: "00112233445566778899AABBCCDDEEFF",
        dst: "8EA2B7CA516745BFEAFC49904B496089"
    }
];

describe("AES", () => {
    it("should not accept wrong key length", () => {
       expect(() => new AES(new Uint8Array(10))).toThrowError(/^AES/);
    });

    it("should not accept different key in setKey()", () => {
       const cipher = new AES(new Uint8Array(32));
       expect(() => cipher.setKey(new Uint8Array(16))).toThrowError(/^AES/);
    });
});

describe("AES.encryptBlock", () => {
    it("should correctly encrypt block", () => {
        testVectors.forEach(v => {
            const cipher = new AES(decode(v.key));
            const dst = new Uint8Array(16);
            cipher.encryptBlock(decode(v.src), dst);
            expect(encode(dst)).toBe(v.dst);
        });
    });

    it("should correctly encrypt many blocks with different keys", () => {
        let key = new Uint8Array(32);
        let block = new Uint8Array(16);
        const newKey = new Uint8Array(32);
        for (let i = 0; i < 100; i++) {
            const cipher = new AES(key);
            for (let j = 0; j < 100; j++) {
                cipher.encryptBlock(block, block);
            }
            newKey.set(key.subarray(16, 32)); // move 16 bytes to left
            newKey.set(block, 16); // fill the rest 16 bytes with block
            key.set(newKey);
        }
        expect(encode(block)).toBe("3A6FD932F608835F1F56D9DC1FCECFA3");
    });
});

describe("AES.decryptBlock", () => {
    it("should correctly decrypt block", () => {
        testVectors.forEach(v => {
            const cipher = new AES(decode(v.key));
            const src = new Uint8Array(16);
            cipher.decryptBlock(decode(v.dst), src);
            expect(encode(src)).toBe(v.src);
        });
    });

    it("should correctly decrypt many blocks with different keys", () => {
        let key = new Uint8Array(32);
        let block = new Uint8Array(16);
        const newKey = new Uint8Array(32);
        for (let i = 0; i < 100; i++) {
            const cipher = new AES(key);
            for (let j = 0; j < 100; j++) {
                cipher.decryptBlock(block, block);
            }
            newKey.set(key.subarray(16, 32)); // move 16 bytes to left
            newKey.set(block, 16); // fill the rest 16 bytes with block
            key.set(newKey);
        }
        expect(encode(block)).toBe("551EC0EA8EA69F1FC4EF95E6420AD4B6");
    });
});
