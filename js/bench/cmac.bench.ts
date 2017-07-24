// Copyright (C) 2016 Dmitry Chestnykh
// MIT License. See LICENSE file for details.

import { benchmark, report, byteSeq } from "./benchmark";

import AES from "../src/internal/polyfill/aes";
import CMAC from "../src/internal/polyfill/aes_cmac";

const buf8192 = byteSeq(8192);
const buf1024 = byteSeq(1024);
const buf32 = byteSeq(32);
const aes = new AES(byteSeq(32));

report("CMAC-AES-256 8K", benchmark(() => (new CMAC(aes)).update(buf8192).digest(), buf8192.length));
report("CMAC-AES-256 1K", benchmark(() => (new CMAC(aes)).update(buf1024).digest(), buf1024.length));
report("CMAC-AES-256 32", benchmark(() => (new CMAC(aes)).update(buf32).digest(), buf32.length));
