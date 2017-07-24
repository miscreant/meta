// Copyright (C) 2017 Dmitry Chestnykh
// MIT License. See LICENSE file for details.

import { benchmark, report, byteSeq } from "./benchmark";

import AES from "../src/internal/polyfill/aes";
import SIV from "../src/internal/aes_siv";

const buf8192 = byteSeq(8192);
const buf1111 = byteSeq(1111);

const key = byteSeq(64);
const ad = [byteSeq(12)];
const siv = new SIV(AES, key);

report("AES-SIV seal 8K", benchmark(() => siv.seal(ad, buf8192), buf8192.length));
report("AES-SIV seal 1111", benchmark(() => siv.seal(ad, buf1111), buf1111.length));

const sealed8192 = siv.seal(ad, buf8192);
const sealed1111 = siv.seal(ad, buf1111);

report("AES-SIV open 8K", benchmark(() => siv.open(ad, sealed8192), buf8192.length));
report("AES-SIV open 1111", benchmark(() => siv.open(ad, sealed1111), buf1111.length));

sealed8192[0] ^= sealed8192[0];

report("AES-SIV open (bad)", benchmark(() => siv.open(ad, sealed8192), buf8192.length));
