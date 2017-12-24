import * as fs from "async-file";
import TJSON from "tjson-js";

/** AES-SIV test vectors */
export class AesSivExample {
  static readonly DEFAULT_EXAMPLES_PATH = "../vectors/aes_siv.tjson";

  public readonly name: string;
  public readonly key: Uint8Array;
  public readonly ad: Uint8Array[];
  public readonly plaintext: Uint8Array;
  public readonly ciphertext: Uint8Array;

  static async loadAll(): Promise<AesSivExample[]> {
    return AesSivExample.loadFromFile(AesSivExample.DEFAULT_EXAMPLES_PATH);
  }

  static async loadFromFile(filename: string): Promise<AesSivExample[]> {
    let tjson = TJSON.parse(await fs.readFile(filename, "utf8"));
    return tjson["examples"].map((ex: any) => {
      let obj = Object.create(AesSivExample.prototype);
      return Object.assign(obj, ex);
    });
  }
}

/** AES-PMAC-SIV test vectors */
export class AesPmacSivExample {
  static readonly DEFAULT_EXAMPLES_PATH = "../vectors/aes_pmac_siv.tjson";

  public readonly name: string;
  public readonly key: Uint8Array;
  public readonly ad: Uint8Array[];
  public readonly plaintext: Uint8Array;
  public readonly ciphertext: Uint8Array;

  static async loadAll(): Promise<AesPmacSivExample[]> {
    return AesPmacSivExample.loadFromFile(AesPmacSivExample.DEFAULT_EXAMPLES_PATH);
  }

  static async loadFromFile(filename: string): Promise<AesPmacSivExample[]> {
    let tjson = TJSON.parse(await fs.readFile(filename, "utf8"));
    return tjson["examples"].map((ex: any) => {
      let obj = Object.create(AesPmacSivExample.prototype);
      return Object.assign(obj, ex);
    });
  }
}

/** AEAD (AES-SIV/AES-PMAC-SIV) test vectors */
export class AEADExample {
  static readonly DEFAULT_EXAMPLES_PATH = "../vectors/aes_siv_aead.tjson";

  public readonly name: string;
  public readonly alg: string;
  public readonly key: Uint8Array;
  public readonly ad: Uint8Array;
  public readonly nonce: Uint8Array;
  public readonly plaintext: Uint8Array;
  public readonly ciphertext: Uint8Array;

  static async loadAll(): Promise<AEADExample[]> {
    return AEADExample.loadFromFile(AEADExample.DEFAULT_EXAMPLES_PATH);
  }

  static async loadFromFile(filename: string): Promise<AEADExample[]> {
    let tjson = TJSON.parse(await fs.readFile(filename, "utf8"));
    return tjson["examples"].map((ex: any) => {
      let obj = Object.create(AEADExample.prototype);
      return Object.assign(obj, ex);
    });
  }
}

export class STREAMBlock {
  public readonly ad: Uint8Array;
  public readonly plaintext: Uint8Array;
  public readonly ciphertext: Uint8Array;
}

/** STREAM (AES-SIV/AES-PMAC-SIV) test vectors */
export class STREAMExample {
  static readonly DEFAULT_EXAMPLES_PATH = "../vectors/aes_siv_stream.tjson";

  public readonly name: string;
  public readonly alg: string;
  public readonly key: Uint8Array;
  public readonly nonce: Uint8Array;
  public readonly blocks: STREAMBlock[];

  static async loadAll(): Promise<STREAMExample[]> {
    return STREAMExample.loadFromFile(STREAMExample.DEFAULT_EXAMPLES_PATH);
  }

  static async loadFromFile(filename: string): Promise<STREAMExample[]> {
    let tjson = TJSON.parse(await fs.readFile(filename, "utf8"));
    return tjson["examples"].map((ex: any) => {
      let obj = Object.create(STREAMExample.prototype);
      return Object.assign(obj, ex);
    });
  }
}

/** AES (raw block function) test vectors */
export class AesExample {
  static readonly DEFAULT_EXAMPLES_PATH = "../vectors/aes.tjson";

  public readonly key: Uint8Array;
  public readonly src: Uint8Array;
  public readonly dst: Uint8Array;

  static async loadAll(): Promise<AesExample[]> {
    return AesExample.loadFromFile(AesExample.DEFAULT_EXAMPLES_PATH);
  }

  static async loadFromFile(filename: string): Promise<AesExample[]> {
    let tjson = TJSON.parse(await fs.readFile(filename, "utf8"));
    return tjson["examples"].map((ex: any) => {
      let obj = Object.create(AesExample.prototype);
      return Object.assign(obj, ex);
    });
  }
}

/** AES-CTR test vectors */
export class AesCtrExample {
  static readonly DEFAULT_EXAMPLES_PATH = "../vectors/aes_ctr.tjson";

  public readonly key: Uint8Array;
  public readonly iv: Uint8Array;
  public readonly plaintext: Uint8Array;
  public readonly ciphertext: Uint8Array;

  static async loadAll(): Promise<AesCtrExample[]> {
    return AesCtrExample.loadFromFile(AesCtrExample.DEFAULT_EXAMPLES_PATH);
  }

  static async loadFromFile(filename: string): Promise<AesCtrExample[]> {
    let tjson = TJSON.parse(await fs.readFile(filename, "utf8"));
    return tjson["examples"].map((ex: any) => {
      let obj = Object.create(AesCtrExample.prototype);
      return Object.assign(obj, ex);
    });
  }
}

/** AES-CMAC test vectors */
export class AesCmacExample {
  static readonly DEFAULT_EXAMPLES_PATH = "../vectors/aes_cmac.tjson";

  public readonly key: Uint8Array;
  public readonly message: Uint8Array;
  public readonly tag: Uint8Array;

  static async loadAll(): Promise<AesCmacExample[]> {
    return AesCmacExample.loadFromFile(AesCmacExample.DEFAULT_EXAMPLES_PATH);
  }

  static async loadFromFile(filename: string): Promise<AesCmacExample[]> {
    let tjson = TJSON.parse(await fs.readFile(filename, "utf8"));
    return tjson["examples"].map((ex: any) => {
      let obj = Object.create(AesCmacExample.prototype);
      return Object.assign(obj, ex);
    });
  }
}

/** AES-PMAC test vectors */
export class AesPmacExample {
  static readonly DEFAULT_EXAMPLES_PATH = "../vectors/aes_pmac.tjson";

  public readonly key: Uint8Array;
  public readonly message: Uint8Array;
  public readonly tag: Uint8Array;

  static async loadAll(): Promise<AesPmacExample[]> {
    return AesPmacExample.loadFromFile(AesPmacExample.DEFAULT_EXAMPLES_PATH);
  }

  static async loadFromFile(filename: string): Promise<AesPmacExample[]> {
    let tjson = TJSON.parse(await fs.readFile(filename, "utf8"));
    return tjson["examples"].map((ex: any) => {
      let obj = Object.create(AesPmacExample.prototype);
      return Object.assign(obj, ex);
    });
  }
}

/** dbl() test vectors */
export class DblExample {
  static readonly DEFAULT_EXAMPLES_PATH = "../vectors/dbl.tjson";

  public readonly input: Uint8Array;
  public readonly output: Uint8Array;

  static async loadAll(): Promise<DblExample[]> {
    return DblExample.loadFromFile(DblExample.DEFAULT_EXAMPLES_PATH);
  }

  static async loadFromFile(filename: string): Promise<DblExample[]> {
    let tjson = TJSON.parse(await fs.readFile(filename, "utf8"));
    return tjson["examples"].map((ex: any) => {
      let obj = Object.create(DblExample.prototype);
      return Object.assign(obj, ex);
    });
  }
}
