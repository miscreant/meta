// Copyright (C) 2016 Dmitry Chestnykh
// MIT License. See LICENSE file for details.

import { AES } from "./aes";
import { benchmark, report, byteSeq } from "@stablelib/benchmark";

const key = byteSeq(32);
const cipher = new AES(key);
const src = byteSeq(16);
const dst = new Uint8Array(16);

report("AES-256 init", benchmark(() => new AES(key)));
report("AES-256 encrypt", benchmark(() => cipher.encryptBlock(src, dst), src.length));
report("AES-256 decrypt", benchmark(() => cipher.decryptBlock(src, dst), src.length));
