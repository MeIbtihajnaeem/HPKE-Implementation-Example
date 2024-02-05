import { Aes128Gcm, CipherSuite, HkdfSha256 } from "@hpke/core";
import { DhkemX25519HkdfSha256 } from "@hpke/dhkem-x25519";
import { randomBytes } from "crypto";

function toHexString(byteArray) {
    return Buffer.from(byteArray).toString('hex');
}

export const doHPKE = async ({ _mode, _ikem, _psk, _psk_id, _info, _msg1 }) => {
    try {
        // Initialize CipherSuite
        const suite = new CipherSuite({
            kem: new DhkemX25519HkdfSha256(),
            kdf: new HkdfSha256(),
            aead: new Aes128Gcm(),
        });

        // Generate key pairs for Alice and Bob
        const ikem = _ikem;
        const psk = _psk;
        const psk_id = _psk_id;

        console.log("Initialization started...");

        const alic = await suite.kem.generateKeyPair();
        const bob = await suite.kem.deriveKeyPair(ikem);

        console.log("Initialization completed successfully.");

        // Generate random info
        const info = _info;

        console.log("Mode: " + _mode);
        console.log("KEM_ID: " + suite.kem.id);
        console.log("KDF_ID: " + suite.kdf.id);
        console.log("AEAD_ID: " + suite.aead.id);
        console.log("INFO: " + toHexString(info.buffer));
        console.log("IKEM: " + toHexString(ikem));
        console.log("pkS: " + toHexString(alic.publicKey.key));
        console.log("skS: " + toHexString(alic.privateKey.key));
        console.log("pkR: " + toHexString(bob.publicKey.key));
        console.log("skR: " + toHexString(bob.privateKey.key));

        // Create sender and recipient contexts
        const alicContext = await suite.createSenderContext({
            recipientPublicKey: bob.publicKey,
            info: info,
            psk: {
                id: psk_id,
                key: toHexString(psk),
            },
        });

        const bobContext = await suite.createRecipientContext({
            info: info,
            enc: alicContext.enc,
            recipientKey: bob.privateKey,
            psk: {
                id: psk_id,
                key: toHexString(psk),
            },
        });

        console.log("PSK_ID: " + toHexString(psk_id));
        console.log("PSK: " + toHexString(psk));
        console.log("ENC: " + toHexString(alicContext.enc));
        console.log("Pre Shared Key: " + toHexString(psk));

        // Generate random messages and AADs
        const msg1 = _msg1;
        const aad1 = randomBytes(suite.aead.nonceSize);

        console.log("Raw messages:");
        console.log("  Msg1:", toHexString(msg1));
        console.log("  AAD1:", toHexString(aad1));

        // Encrypt messages
        const enc1 = await alicContext.seal(msg1, aad1);

        console.log("Encrypted messages:");
        console.log("  Enc1:", toHexString(enc1));

        // Decrypt messages
        const dec1 = await bobContext.open(enc1, aad1);

        console.log("Decrypted messages:");
        console.log("  Dec1:", toHexString(dec1));

        return dec1;
    } catch (e) {
        console.error("Failed:", e.message);
        return "";
    }
};

// Call the asynchronous function properly
// doHPKE();
// module.exports={doHPKE}
