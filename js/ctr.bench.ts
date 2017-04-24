// Copyright (C) 2016 Dmitry Chestnykh
// MIT License. See LICENSE file for details.

import { AES } from "@stablelib/aes";
import { benchmark, report, byteSeq } from "@stablelib/benchmark";
import { CTR } from "./ctr";

const buf8192 = byteSeq(8192);
const buf1111 = byteSeq(1111);

const key = byteSeq(32);
const iv = new Uint8Array(16);

const cipher = new AES(key);
const ctr = new CTR(cipher, iv);

report("AES-CTR 8K", benchmark(() => ctr.streamXOR(buf8192, buf8192), buf8192.length));
report("AES-CTR 1111", benchmark(() => ctr.streamXOR(buf1111, buf1111), buf1111.length));
