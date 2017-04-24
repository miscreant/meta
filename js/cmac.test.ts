// Copyright (C) 2016 Dmitry Chestnykh
// MIT License. See LICENSE file for details.

import { CMAC } from "./cmac";
import { AES } from "@stablelib/aes";
import { encode, decode } from "@stablelib/hex";

const key128 = "2B7E151628AED2A6ABF7158809CF4F3C";
const key256 = "603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4";

const vectors = [
    {
        key: key128,
        input: "",
        result: "BB1D6929E95937287FA37D129B756746"
    },
    {
        key: key128,
        input: "6BC1BEE22E409F96E93D7E117393172A",
        result: "070A16B46B4D4144F79BDD9DD04A287C"
    },
    {
        key: key128,
        input: "6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E5130C81C46A35CE411",
        result: "DFA66747DE9AE63030CA32611497C827"
    },
    {
        key: key128,
        input: "6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E5130C81C46A35CE411" +
        "E5FBC1191A0A52EFF69F2445DF4F9B17AD2B417BE66C3710",
        result: "51F0BEBF7E3B9D92FC49741779363CFE"
    },
    {
        key: key256,
        input: "",
        result: "028962F61B7BF89EFC6B551F4667D983"
    },
    {
        key: key256,
        input: "6BC1BEE22E409F96E93D7E117393172A",
        result: "28A7023F452E8F82BD4BF28D8C37C35C"
    },
    {
        key: key256,
        input: "6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E5130C81C46A35CE411",
        result: "AAF3D8F1DE5640C232F5B169B9C911E6"
    },
    {
        key: key256,
        input: "6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E5130C81C46A35CE411" +
        "E5FBC1191A0A52EFF69F2445DF4F9B17AD2B417BE66C3710",
        result: "E1992190549F6ED5696A2C056C315410"
    }
];

describe("CMAC", () => {
    it("should produce correct results for test vectors", () => {
        vectors.forEach(v => {
            const mac = new CMAC(new AES(decode(v.key), true));
            mac.update(decode(v.input));
            expect(encode(mac.digest())).toBe(v.result);
        });
    });
});
