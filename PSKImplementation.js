import { Aes128Gcm, CipherSuite, HkdfSha256 } from "@hpke/core";
import { DhkemX25519HkdfSha256 } from "@hpke/dhkem-x25519";
import { randomBytes } from "crypto";

function toHexString(byteArray) {
    return Buffer.from(byteArray).toString('hex');
}

async function doHPKE() {
    try {
        // Initialize CipherSuite
        const suite = new CipherSuite({
            kem: new DhkemX25519HkdfSha256(),
            kdf: new HkdfSha256(),
            aead: new Aes128Gcm(),
        });

        const psk = randomBytes(32);
        const psk_id = randomBytes(32);
        // Generate key pairs for Alice and Bob
        const alic = await suite.kem.generateKeyPair();
        const bob = await suite.kem.generateKeyPair();

        // Generate random info
        const info = randomBytes(8);

        // Create sender and recipient contexts
        const alicContext = await suite.createSenderContext({
            recipientPublicKey: bob.publicKey,
            info: info,
            psk: {
                id: psk_id,
                key: psk
            }
        });

        const bobContext = await suite.createRecipientContext({
            info: info,
            enc: alicContext.enc,
            recipientKey: bob.privateKey,
            psk: {
                id: psk_id,
                key: psk
            }
        });

        // Generate random messages and AADs
        const msg1 = randomBytes(32);
        const aad1 = randomBytes(suite.aead.nonceSize);
        const msg2 = randomBytes(32);
        const aad2 = randomBytes(suite.aead.nonceSize);

        console.log("Raw messages:");
        console.log("  Msg1:", toHexString(msg1));
        console.log("  Msg2:", toHexString(msg2));
        console.log("  AAD1:", toHexString(aad1));
        console.log("  AAD2:", toHexString(aad2));

        // Encrypt messages
        const enc1 = await alicContext.seal(msg1, aad1);
        const enc2 = await alicContext.seal(msg2, aad2);

        console.log("Encrypted messages:");
        console.log("  Enc1:", toHexString(enc1));
        console.log("  Enc2:", toHexString(enc2));

        // Decrypt messages
        const dec1 = await bobContext.open(enc1, aad1);
        const dec2 = await bobContext.open(enc2, aad2);

        console.log("Decrypted messages:");
        console.log("  Dec1:", toHexString(dec1));
        console.log("  Dec2:", toHexString(dec2));
    } catch (e) {
        console.log("Failed:", e.message);
    }
}

// Call the asynchronous function properly
doHPKE();
