import { expect } from "chai";
import { doHPKE } from "./test_vector1.js";
import { Aes128Gcm, CipherSuite, HkdfSha256 } from "@hpke/core";
import { DhkemX25519HkdfSha256 } from "@hpke/dhkem-x25519";
import { randomBytes } from "crypto";

describe('Mode: 3 ,  kem:  DhkemX25519HkdfSha256, kdf: new HkdfSha256, aead: new Aes128Gcm', async function () {
    const ikem = randomBytes(32);
    const psk = randomBytes(32);
    const psk_id = randomBytes(32);
    const info = randomBytes(16);
    const msg1 = randomBytes(32);
    const result = await doHPKE({
        _mode: 3, _ikem: ikem, _psk: psk,
        _psk_id: psk_id, _info: info, _msg1: msg1, 
    });
    expect(result).equals(msg1);
})