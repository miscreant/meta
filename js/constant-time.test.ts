// Copyright (C) 2016 Dmitry Chestnykh
// MIT License. See LICENSE file for details.

import { select, lessOrEqual, compare, equal } from "./constant-time";

describe("constant-time.select", () => {
    it("should select correct value", () => {
        expect(select(1, 2, 3)).toBe(2);
        expect(select(1, 3, 2)).toBe(3);
        expect(select(0, 2, 3)).toBe(3);
        expect(select(0, 3, 2)).toBe(2);
    });
});

describe("constant-time.lessOrEqual", () => {
    it("should return correct result", () => {
        expect(lessOrEqual(0, 0)).toBe(1);
        expect(lessOrEqual(0, Math.pow(2, 31) - 1)).toBe(1);
        expect(lessOrEqual(2, 3)).toBe(1);
        expect(lessOrEqual(3, 3)).toBe(1);
        expect(lessOrEqual(4, 3)).toBe(0);
        expect(lessOrEqual(5, 3)).toBe(0);
    });
});

describe("constant-time.compare", () => {
    const a = new Uint8Array([1, 2, 3, 4]);
    const b = new Uint8Array([1, 2, 3, 4]);
    const c = new Uint8Array([1, 2, 5, 4]);
    const d = new Uint8Array([1, 2, 3]);
    const z = new Uint8Array(0);

    it("should return 0 if inputs have different lenghts", () => {
        expect(compare(a, d)).toBe(0);
    });

    it("should return 1 if inputs are equal", () => {
        expect(compare(a, b)).toBe(1);
    });

    it("should return 0 if inputs are not equal", () => {
        expect(compare(a, c)).toBe(0);
    });

    it("should return 1 if given zero-length inputs ", () => {
        expect(compare(z, z)).toBe(1);
    });

});

describe("constant-time.equal", () => {
    const a = new Uint8Array([1, 2, 3, 4]);
    const b = new Uint8Array([1, 2, 3, 4]);
    const c = new Uint8Array([1, 2, 5, 4]);
    const d = new Uint8Array([1, 2, 3]);
    const z = new Uint8Array(0);

    it("should return false if inputs have different lenghts", () => {
        expect(equal(a, d)).toBe(false);
    });

    it("should return true if inputs are equal", () => {
        expect(equal(a, b)).toBe(true);
    });

    it("should return false if inputs are not equal", () => {
        expect(equal(a, c)).toBe(false);
    });

    it("should return false if given zero-length inputs ", () => {
        expect(equal(z, z)).toBe(false);
    });

});
