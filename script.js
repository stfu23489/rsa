// Tab functionality
function switchTab(tabId, clickedButton) {
    // Hide all tab contents
    document.querySelectorAll('.tab-content').forEach(content => {
        content.classList.remove('active');
    });

    // Remove active class from all tab buttons
    document.querySelectorAll('.tab-button').forEach(button => {
        button.classList.remove('active', 'border-blue-600');
        button.classList.add('border-transparent');
    });

    // Show selected tab content
    document.getElementById(tabId).classList.add('active');

    // Add active class to clicked button
    clickedButton.classList.add('active', 'border-blue-600');
    clickedButton.classList.remove('border-transparent');
}

// Toggle password visibility
function togglePasswordVisibility(inputId) {
    const input = document.getElementById(inputId);
    const button = input.nextElementSibling;

    if (input.type === 'password') {
        input.type = 'text';
        button.innerHTML = '<i class="fas fa-eye-slash"></i>';
    } else {
        input.type = 'password';
        button.innerHTML = '<i class="fas fa-eye"></i>';
    }
}

// UTILS
// Converts ArrayBuffer to Base64 string
function ab2b64(buf) {
    const bytes = new Uint8Array(buf);
    let binary = '';
    for(let b of bytes) binary += String.fromCharCode(b);
    return btoa(binary);
}

// Converts Base64 string to ArrayBuffer
function b642ab(str) {
    const binary = atob(str);
    const len = binary.length;
    const buf = new Uint8Array(len);
    for(let i=0; i<len; i++) buf[i] = binary.charCodeAt(i);
    return buf.buffer;
}

// Concatenates multiple Uint8Arrays into a single one
function concatArrays(...arrays) {
    let totalLength = arrays.reduce((acc, arr) => acc + arr.length, 0);
    let result = new Uint8Array(totalLength);
    let offset = 0;
    for(let arr of arrays){
        result.set(arr, offset);
        offset += arr.length;
    }
    return result;
}

// Removes PEM header/footer and all whitespace
function stripPemHeaderFooter(pem) {
    return pem.replace(/-----BEGIN [^-]+-----/, '')
            .replace(/-----END [^-]+-----/, '')
            .replace(/\s+/g, '');
}

// Converts PEM format to raw Base64 string
function pemToBase64(pem) {
    return stripPemHeaderFooter(pem);
}

// Formats a raw Base64 string into PEM format
function toPem(base64, label) {
    let formatted = base64.match(/.{1,64}/g).join('\n');
    return `-----BEGIN ${label}-----\n${formatted}\n-----END ${label}-----`;
}

// Imports a public key from PEM format for encryption
async function importPublicKeyFromPem(pem) {
    const b64 = pemToBase64(pem);
    const spki = b642ab(b64);
    return crypto.subtle.importKey('spki', spki, {name:'RSA-OAEP', hash:'SHA-256'}, true, ['encrypt']);
}

// Imports a private key from PEM format for decryption
async function importPrivateKeyFromPem(pem) {
    const b64 = pemToBase64(pem);
    const pkcs8 = b642ab(b64);
    return crypto.subtle.importKey('pkcs8', pkcs8, {name:'RSA-OAEP', hash:'SHA-256'}, true, ['decrypt']);
}

// Imports a public key from PEM format for signature verification
async function importSignPublicKeyFromPem(pem) {
    const b64 = pemToBase64(pem);
    const spki = b642ab(b64);
    return crypto.subtle.importKey('spki', spki, {name:'RSASSA-PKCS1-v1_5', hash:'SHA-256'}, true, ['verify']);
}

// Imports a private key from PEM format for signing
async function importSignPrivateKeyFromPem(pem) {
    const b64 = pemToBase64(pem);
    const pkcs8 = b642ab(b64);
    return crypto.subtle.importKey('pkcs8', pkcs8, {name:'RSASSA-PKCS1-v1_5', hash:'SHA-256'}, true, ['sign']);
}

// Exports a public key to PEM format
async function exportPublicKeyToPem(key) {
    const spki = await crypto.subtle.exportKey('spki', key);
    return toPem(ab2b64(spki), "PUBLIC KEY");
}

// Exports a private key to PEM format
async function exportPrivateKeyToPem(key) {
    const pkcs8 = await crypto.subtle.exportKey('pkcs8', key);
    return toPem(ab2b64(pkcs8), "PRIVATE KEY");
}

// DERIVE AES-GCM KEY FROM PASSPHRASE + SALT (PBKDF2)
// Derives an AES-GCM key using PBKDF2 from a passphrase and salt
async function deriveKey(passphrase, salt) {
    const enc = new TextEncoder();
    const baseKey = await crypto.subtle.importKey(
        "raw",
        enc.encode(passphrase),
        "PBKDF2",
        false,
        ["deriveKey"]
    );

    return crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt,
            iterations: 300000, // High iteration count for security
            hash: "SHA-256"
        },
        baseKey,
        { name: "AES-GCM", length: 256 }, // AES-256 key
        false,
        ["encrypt", "decrypt"]
    );
}

// Encrypts data using AES-GCM
async function aesGcmEncrypt(key, data) {
    const iv = crypto.getRandomValues(new Uint8Array(12)); // 96-bit IV recommended for AES-GCM
    const ciphertext = await crypto.subtle.encrypt({name:"AES-GCM", iv}, key, data);
    return { iv, ciphertext: new Uint8Array(ciphertext) };
}

// Decrypts data using AES-GCM
async function aesGcmDecrypt(key, iv, ciphertext) {
    return crypto.subtle.decrypt({name:"AES-GCM", iv}, key, ciphertext);
}

// RSA Key Generation (Enc + Sign)
// Generates RSA-OAEP (encryption) and RSASSA-PKCS1-v1_5 (signing) key pairs
async function generateRSAKeyPairs(modulusLength) {
    // Generate RSA-OAEP keys for encryption/decryption
    const encKeys = await crypto.subtle.generateKey(
        {
            name: "RSA-OAEP",
            modulusLength: modulusLength,
            publicExponent: new Uint8Array([1,0,1]), // 65537
            hash: "SHA-256"
        },
        true, // extractable
        ["encrypt", "decrypt"]
    );

    // Generate RSASSA-PKCS1-v1_5 keys for signing/verification
    const signKeys = await crypto.subtle.generateKey(
        {
            name: "RSASSA-PKCS1-v1_5",
            modulusLength: modulusLength,
            publicExponent: new Uint8Array([1,0,1]), // 65537
            hash: "SHA-256"
        },
        true, // extractable
        ["sign", "verify"]
    );
    return { encKeys, signKeys };
}

// EXPORT KEYS TO RAW BUFFERS (SPKI/PKCS8)
// Exports all key parts to raw Uint8Array buffers
async function exportAllKeysRaw(keys) {
    const encPubRaw = new Uint8Array(await crypto.subtle.exportKey("spki", keys.encKeys.publicKey));
    const encPrivRaw = new Uint8Array(await crypto.subtle.exportKey("pkcs8", keys.encKeys.privateKey));
    const signPubRaw = new Uint8Array(await crypto.subtle.exportKey("spki", keys.signKeys.publicKey));
    const signPrivRaw = new Uint8Array(await crypto.subtle.exportKey("pkcs8", keys.signKeys.privateKey));
    return { encPubRaw, encPrivRaw, signPubRaw, signPrivRaw };
}

// Combine keys as length-prefixed slices: [4-byte big endian length][bytes] x4
function combineRawKeys(...arrays) {
    let totalLength = arrays.reduce((acc, arr) => acc + arr.length + 4, 0); // +4 for length prefix
    let result = new Uint8Array(totalLength);
    let offset = 0;
    for(let arr of arrays){
        const length = arr.length;
        const view = new DataView(result.buffer);
        view.setUint32(offset, length, false); // false for big-endian
        offset += 4;
        result.set(arr, offset);
        offset += arr.length;
    }
    return result;
}

// Parses combined raw keys from a buffer
function parseCombinedRawKeys(buf) {
    let offset = 0;
    const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);

    function readLength() {
        if (offset + 4 > buf.length) throw new Error("Invalid key data length (missing length prefix)");
        let len = view.getUint32(offset, false); // false for big-endian
        offset += 4;
        return len;
    }

    function readSlice(len) {
        if (offset + len > buf.length) throw new Error("Invalid key data length (slice too long)");
        let slice = buf.slice(offset, offset + len);
        offset += len;
        return slice;
    }

    const encPubRaw = readSlice(readLength());
    const encPrivRaw = readSlice(readLength());
    const signPubRaw = readSlice(readLength());
    const signPrivRaw = readSlice(readLength());
    return { encPubRaw, encPrivRaw, signPubRaw, signPrivRaw };
}

// Encrypt combined keys raw buffer with passphrase using AES-GCM (salt + iv prepended)
async function encryptKeysWithPassphrase(pass, combinedRawKeys) {
    const salt = crypto.getRandomValues(new Uint8Array(16)); // 16-byte salt
    const key = await deriveKey(pass, salt);
    const { iv, ciphertext } = await aesGcmEncrypt(key, combinedRawKeys);
    const encryptedBlob = concatArrays(salt, iv, ciphertext);
    return encryptedBlob;
}

// Decrypt keys blob with passphrase
async function decryptKeysWithPassphrase(pass, encryptedBlob) {
    if (encryptedBlob.length < 16 + 12) { // 16 bytes for salt, 12 for IV
        throw new Error("Encrypted keys blob too short.");
    }
    const salt = encryptedBlob.slice(0, 16);
    const iv = encryptedBlob.slice(16, 28);
    const ciphertext = encryptedBlob.slice(28);
    const key = await deriveKey(pass, salt);
    const rawKeysBuf = await aesGcmDecrypt(key, iv, ciphertext);
    return new Uint8Array(rawKeysBuf);
}

// Convert raw keys (Uint8Arrays) to PEM strings by base64 encoding + PEM formatting
function rawKeyToPem(rawKey, type) {
    return toPem(ab2b64(rawKey), type);
}

// Parse PEM string to raw Uint8Array buffer
function pemToRawKey(pem) {
    return new Uint8Array(b642ab(pemToBase64(pem)));
}

// Parse PEM textboxes to raw keys for export & encryption
function readKeysFromTextBoxes() {
    const pubPem = document.getElementById('publicKeyBox').value.trim();
    const privPem = document.getElementById('privateKeyBox').value.trim();

    if (!pubPem || !privPem) throw new Error("Your Public and Private key PEMs must not be empty for export.");

    // Assume these PEMs are encoding *encryption* keys
    const encPubRaw = pemToRawKey(pubPem);
    const encPrivRaw = pemToRawKey(privPem);

    // For simplicity, reuse same keys for signing (could separate)
    // So we will use same enc keys for sign keys to keep demo simple
    // Otherwise, you'd add additional textboxes or handling for sign keys
    const signPubRaw = encPubRaw;
    const signPrivRaw = encPrivRaw;
    return { encPubRaw, encPrivRaw, signPubRaw, signPrivRaw };
}

// Import your own keys freshly from PEM strings for encryption/signing operations
async function importYourKeysFromTextBoxes() {
    const pubPem = document.getElementById('publicKeyBox').value.trim();
    const privPem = document.getElementById('privateKeyBox').value.trim();
    if (!pubPem || !privPem) throw new Error("Your Public and Private key PEMs must not be empty.");

    // Import encryption keys
    const encPublicKey = await importPublicKeyFromPem(pubPem);
    const encPrivateKey = await importPrivateKeyFromPem(privPem);

    // Import signing keys same as enc keys here for simplicity (in real world separate)
    const signPublicKey = await importSignPublicKeyFromPem(pubPem);
    const signPrivateKey = await importSignPrivateKeyFromPem(privPem);
    return {
        encKeys: { publicKey: encPublicKey, privateKey: encPrivateKey },
        signKeys: { publicKey: signPublicKey, privateKey: signPrivateKey }
    };
}

// Encrypt and sign message string, reads YOUR private key and RECIPIENT's public key
async function encryptAndSignMessage(message) {
    const yourKeys = await importYourKeysFromTextBoxes();
    const recipientPubPem = document.getElementById('recipientPublicKeyBox').value.trim();

    if (!recipientPubPem) {
        throw new Error("Recipient's Public Key must be provided to encrypt the message.");
    }

    const recipientEncPublicKey = await importPublicKeyFromPem(recipientPubPem);

    // Determine the RSA key's actual byte length from the public key's modulus 'n'
    const recipientKeyJwk = await crypto.subtle.exportKey("jwk", recipientEncPublicKey);
    const rsaKeyByteLength = Math.ceil(recipientKeyJwk.n.length * 3 / 4); // Base64 decoded length of 'n'

    const encoder = new TextEncoder();
    const messageBytes = encoder.encode(message);

    // Generate AES key
    const aesKey = await crypto.subtle.generateKey(
        {name:"AES-GCM", length:256}, true, ["encrypt", "decrypt"]);

    const iv = crypto.getRandomValues(new Uint8Array(12));

    // Encrypt message
    const ciphertext = new Uint8Array(await crypto.subtle.encrypt({name:"AES-GCM", iv}, aesKey, messageBytes));

    // Export AES key raw
    const rawAesKey = new Uint8Array(await crypto.subtle.exportKey("raw", aesKey));

    // Encrypt AES key with RECIPIENT's RSA-OAEP public key
    const encryptedAESKeyBuf = new Uint8Array(await crypto.subtle.encrypt({name:"RSA-OAEP"}, recipientEncPublicKey, rawAesKey));
    // Crucial change: Store the actual byte length produced by the RSA encryption operation
    const actualRsaOutputLength = encryptedAESKeyBuf.byteLength;

    // Sign original message with YOUR RSA private signing key
    const signatureBuf = new Uint8Array(await crypto.subtle.sign({name:"RSASSA-PKCS1-v1_5"}, yourKeys.signKeys.privateKey, messageBytes));

    // Assert that signatureBuf length also matches actualRsaOutputLength
    if (signatureBuf.byteLength !== actualRsaOutputLength) {
        console.warn("Signature buffer length does not match encrypted AES key buffer length. This might cause issues.");
    }

    // Prepend actualRsaOutputLength as a 4-byte big-endian integer
    const rsaOutputLengthBytes = new Uint8Array(4);
    new DataView(rsaOutputLengthBytes.buffer).setUint32(0, actualRsaOutputLength, false); // false for big-endian

    // Concatenate: RSA_Output_Length(4) + IV(12) + encryptedAESKey(actualRsaOutputLength) + ciphertext + signature(actualRsaOutputLength)
    const finalBlob = concatArrays(rsaOutputLengthBytes, iv, encryptedAESKeyBuf, ciphertext, signatureBuf);
    return ab2b64(finalBlob);
}

// Decrypt and verify message, reads YOUR private key and SENDER's public key (for verification)
async function decryptAndVerifyMessage(base64Blob) {
    const yourKeys = await importYourKeysFromTextBoxes();
    const senderPubPem = document.getElementById('recipientPublicKeyBox').value.trim(); // Assuming recipient key box is used for sender's public key

    if (!senderPubPem) {
        throw new Error("Sender's Public Key must be provided to verify the signature.");
    }

    const senderSignPublicKey = await importSignPublicKeyFromPem(senderPubPem);

    const buf = new Uint8Array(b642ab(base64Blob));

    // Read actualRsaOutputLength from the first 4 bytes
    if (buf.length < 4) {
        throw new Error("Invalid encrypted message length: missing RSA output length.");
    }
    const rsaOutputLength = new DataView(buf.buffer, buf.byteOffset, buf.byteLength).getUint32(0, false);

    const MIN_EXPECTED_LENGTH = 4 + 12 + rsaOutputLength + rsaOutputLength;
    if (buf.length < MIN_EXPECTED_LENGTH) {
        throw new Error(`Invalid encrypted message length. Expected at least ${MIN_EXPECTED_LENGTH} bytes for RSA output length ${rsaOutputLength}, but got ${buf.length}.`);
    }

    let offset = 4; // Start after rsaOutputLength

    const iv = buf.slice(offset, offset + 12);
    offset += 12;

    const encryptedAESKey = buf.slice(offset, offset + rsaOutputLength);
    offset += rsaOutputLength;

    // The signature is always at the end of the combined buffer and its length is rsaOutputLength
    const signature = buf.slice(buf.length - rsaOutputLength);
    // The ciphertext is everything between the end of encryptedAESKey and the start of the signature
    const ciphertext = buf.slice(offset, buf.length - rsaOutputLength);

    // Decrypt AES key with YOUR RSA private key
    const rawAesKeyBuf = await crypto.subtle.decrypt({name:"RSA-OAEP"}, yourKeys.encKeys.privateKey, encryptedAESKey);

    const aesKey = await crypto.subtle.importKey("raw", rawAesKeyBuf, {name:"AES-GCM"}, false, ["decrypt"]);

    // Decrypt ciphertext
    const decryptedBuf = await crypto.subtle.decrypt({name:"AES-GCM", iv}, aesKey, ciphertext);

    // Verify signature on decrypted plaintext using SENDER's public key
    const verified = await crypto.subtle.verify(
        {name:"RSASSA-PKCS1-v1_5"},
        senderSignPublicKey,
        signature,
        decryptedBuf
    );

    const decoder = new TextDecoder();
    const decryptedText = decoder.decode(decryptedBuf);

    return { decryptedText, verified };
}

// Event Listeners for buttons
document.addEventListener('DOMContentLoaded', () => {
    // Generate keys and write PEM to text boxes (encryption and signing keys identical)
    document.getElementById("genKeysBtn").onclick = async () => {
        const genKeysBtn = document.getElementById("genKeysBtn");
        const keySizeInput = document.getElementById("keySizeInput");
        const resultBox = document.getElementById("resultBox");
        const signatureVerificationResult = document.getElementById("signatureVerificationResult");
        const publicKeyBox = document.getElementById("publicKeyBox");
        const privateKeyBox = document.getElementById("privateKeyBox");
        const encryptedKeysBox = document.getElementById("encryptedKeysBox");

        const modulusLength = parseInt(keySizeInput.value, 10);
        if (isNaN(modulusLength) || modulusLength < 1024 || modulusLength % 128 !== 0) {
            // Replaced alert with custom UI message.
            resultBox.value = "Please enter a valid RSA key size (e.g., 1024, 2048, 4096). Must be a multiple of 128.";
            return;
        }

        genKeysBtn.disabled = true;
        genKeysBtn.innerHTML = '<i class="fas fa-spinner animate-spin mr-2"></i> Generating keys...';

        try {
            // Pass the selected modulusLength to the generation function
            const keys = await generateRSAKeyPairs(modulusLength);

            // Export keys to PEM
            const pubPemEnc = await exportPublicKeyToPem(keys.encKeys.publicKey);
            const privPemEnc = await exportPrivateKeyToPem(keys.encKeys.privateKey);

            // For simplicity, use enc keys also as sign keys
            // Write to textareas
            publicKeyBox.value = pubPemEnc;
            privateKeyBox.value = privPemEnc;
            encryptedKeysBox.value = ""; // Clear exported keys when new keys are generated
            resultBox.value = `Keys (RSA-${modulusLength} bits) generated successfully.`;
            signatureVerificationResult.textContent = "Verification status will appear here";
            signatureVerificationResult.className = "w-full p-3 border border-gray-300 dark:border-gray-700 rounded-md bg-gray-100 dark:bg-gray-900";

        } catch (e) {
            resultBox.value = "Key generation failed: " + e.message;
            signatureVerificationResult.textContent = "Verification status will appear here";
            signatureVerificationResult.className = "w-full p-3 border border-gray-300 dark:border-gray-700 rounded-md bg-gray-100 dark:bg-gray-900";
        }

        genKeysBtn.disabled = false;
        genKeysBtn.innerHTML = '<i class="fas fa-plus-circle mr-2"></i> Generate RSA Key Pair';
    };

    // Export keys: read keys from textboxes, combine, encrypt with passphrase, output base64 blob
    document.getElementById("exportKeysBtn").onclick = async () => {
        const exportKeysBtn = document.getElementById("exportKeysBtn");
        const passphraseInput = document.getElementById("passphraseInput");
        const encryptedKeysBox = document.getElementById("encryptedKeysBox");
        const resultBox = document.getElementById("resultBox");
        const signatureVerificationResult = document.getElementById("signatureVerificationResult");

        const pass = passphraseInput.value;
        if (!pass) {
            // Replaced alert with custom UI message.
            resultBox.value = "A passphrase is required to export keys.";
            signatureVerificationResult.textContent = "Verification status will appear here";
            signatureVerificationResult.className = "w-full p-3 border border-gray-300 dark:border-gray-700 rounded-md bg-gray-100 dark:bg-gray-900";
            return;
        }

        exportKeysBtn.disabled = true;
        exportKeysBtn.innerHTML = '<i class="fas fa-spinner animate-spin mr-2"></i> Encrypting keys...';

        try {
            const raw = readKeysFromTextBoxes();
            const combinedRaw = combineRawKeys(raw.encPubRaw, raw.encPrivRaw, raw.signPubRaw, raw.signPrivRaw);
            const encryptedBlob = await encryptKeysWithPassphrase(pass, combinedRaw);
            encryptedKeysBox.value = ab2b64(encryptedBlob);
            resultBox.value = "Keys encrypted and exported.";
            signatureVerificationResult.textContent = "Verification status will appear here";
            signatureVerificationResult.className = "w-full p-3 border border-gray-300 dark:border-gray-700 rounded-md bg-gray-100 dark:bg-gray-900";

        } catch(e) {
            resultBox.value = "Export failed: " + e.message;
            signatureVerificationResult.textContent = "Verification status will appear here";
            signatureVerificationResult.className = "w-full p-3 border border-gray-300 dark:border-gray-700 rounded-md bg-gray-100 dark:bg-gray-900";
        }

        exportKeysBtn.disabled = false;
        exportKeysBtn.innerHTML = '<i class="fas fa-file-export mr-2"></i> Export Keys';
    };

    // Import keys: decrypt base64 blob with passphrase, parse keys, write PEM to textboxes
    document.getElementById("importKeysBtn").onclick = async () => {
        const importKeysBtn = document.getElementById("importKeysBtn");
        const passphraseInput = document.getElementById("passphraseInput");
        const encryptedKeysBox = document.getElementById("encryptedKeysBox");
        const publicKeyBox = document.getElementById("publicKeyBox");
        const privateKeyBox = document.getElementById("privateKeyBox");
        const resultBox = document.getElementById("resultBox");
        const signatureVerificationResult = document.getElementById("signatureVerificationResult");

        const pass = passphraseInput.value;
        const encryptedBase64 = encryptedKeysBox.value.trim();

        if (!encryptedBase64) {
            // Replaced alert with custom UI message.
            resultBox.value = "Paste the encrypted keys in Base64 format to import.";
            signatureVerificationResult.textContent = "Verification status will appear here";
            signatureVerificationResult.className = "w-full p-3 border border-gray-300 dark:border-gray-700 rounded-md bg-gray-100 dark:bg-gray-900";
            return;
        }
         if (!pass) {
            // Replaced alert with custom UI message.
            resultBox.value = "A passphrase is required to import keys.";
            signatureVerificationResult.textContent = "Verification status will appear here";
            signatureVerificationResult.className = "w-full p-3 border border-gray-300 dark:border-gray-700 rounded-md bg-gray-100 dark:bg-gray-900";
            return;
        }

        importKeysBtn.disabled = true;
        importKeysBtn.innerHTML = '<i class="fas fa-spinner animate-spin mr-2"></i> Decrypting keys...';

        try {
            const encryptedBlob = new Uint8Array(b642ab(encryptedBase64));
            const decryptedRaw = await decryptKeysWithPassphrase(pass, encryptedBlob);
            const { encPubRaw, encPrivRaw, signPubRaw, signPrivRaw } = parseCombinedRawKeys(decryptedRaw);

            // Convert raw to PEM strings
            const pubPem = rawKeyToPem(encPubRaw, "PUBLIC KEY");
            const privPem = rawKeyToPem(encPrivRaw, "PRIVATE KEY");

            // We ignore sign keys here, show encryption keys only
            publicKeyBox.value = pubPem;
            privateKeyBox.value = privPem;

            resultBox.value = "Keys successfully decrypted and imported.";
            signatureVerificationResult.textContent = "Verification status will appear here";
            signatureVerificationResult.className = "w-full p-3 border border-gray-300 dark:border-gray-700 rounded-md bg-gray-100 dark:bg-gray-900";

        } catch(e) {
            resultBox.value = "Import failed. Please check the passphrase and data: " + e.message;
            signatureVerificationResult.textContent = "Verification status will appear here";
                signatureVerificationResult.className = "w-full p-3 border border-gray-300 dark:border-gray-700 rounded-md bg-gray-100 dark:bg-gray-900";
        }

        importKeysBtn.disabled = false;
        importKeysBtn.innerHTML = '<i class="fas fa-file-import mr-2"></i> Import Keys';
    };

    // Encrypt message (read YOUR private key and RECIPIENT's public key)
    document.getElementById("encryptBtn").onclick = async () => {
        const encryptBtn = document.getElementById("encryptBtn");
        const messageBox = document.getElementById("messageBox");
        const resultBox = document.getElementById("resultBox");
        const signatureVerificationResult = document.getElementById("signatureVerificationResult");

        const msg = messageBox.value;
        if (!msg) {
            // Replaced alert with custom UI message.
            resultBox.value = "Please enter a message to encrypt.";
            signatureVerificationResult.textContent = "Verification status will appear here";
            signatureVerificationResult.className = "w-full p-3 border border-gray-300 dark:border-gray-700 rounded-md bg-gray-100 dark:bg-gray-900";
            return;
        }

        encryptBtn.disabled = true;
        encryptBtn.innerHTML = '<i class="fas fa-spinner animate-spin mr-2"></i> Encrypting...';

        try {
            const encrypted = await encryptAndSignMessage(msg);
            resultBox.value = encrypted;
            signatureVerificationResult.textContent = "Verification status will appear here";
            signatureVerificationResult.className = "w-full p-3 border border-gray-300 dark:border-gray-700 rounded-md bg-gray-100 dark:bg-gray-900";

        } catch(e) {
            resultBox.value = "Encryption failed: " + e.message;
            signatureVerificationResult.textContent = "Verification status will appear here";
            signatureVerificationResult.className = "w-full p-3 border border-gray-300 dark:border-gray-700 rounded-md bg-gray-100 dark:bg-gray-900";
        }

        encryptBtn.disabled = false;
        encryptBtn.innerHTML = '<i class="fas fa-lock mr-2"></i> Encrypt & Sign';
    };

    // Decrypt message (read YOUR private key and SENDER's public key from recipient box)
    document.getElementById("decryptBtn").onclick = async () => {
        const decryptBtn = document.getElementById("decryptBtn");
        const messageBox = document.getElementById("messageBox");
        const resultBox = document.getElementById("resultBox");
        const signatureVerificationResult = document.getElementById("signatureVerificationResult");

        const blob = messageBox.value.trim();
        if (!blob) {
            // Replaced alert with custom UI message.
            resultBox.value = "Please enter the encrypted message in Base64 format to decrypt.";
            signatureVerificationResult.textContent = "Verification status will appear here";
            signatureVerificationResult.className = "w-full p-3 border border-gray-300 dark:border-gray-700 rounded-md bg-gray-100 dark:bg-gray-900";
            return;
        }

        decryptBtn.disabled = true;
        decryptBtn.innerHTML = '<i class="fas fa-spinner animate-spin mr-2"></i> Decrypting...';

        try {
            const { decryptedText, verified } = await decryptAndVerifyMessage(blob);
            resultBox.value = decryptedText;

            if (verified) {
                signatureVerificationResult.textContent = "Signature verified ✅";
                signatureVerificationResult.className = "w-full p-3 border border-green-500 rounded-md bg-green-100 dark:bg-green-900";
            } else {
                signatureVerificationResult.textContent = "Incorrect signature ⚠️";
                signatureVerificationResult.className = "w-full p-3 border border-red-500 rounded-md bg-red-100 dark:bg-red-900";
            }

        } catch(e) {
            resultBox.value = "Decryption or verification failed: " + e.message;
            signatureVerificationResult.textContent = "Verification status will appear here";
                signatureVerificationResult.className = "w-full p-3 border border-gray-300 dark:border-gray-700 rounded-md bg-gray-100 dark:bg-gray-900";
        }

        decryptBtn.disabled = false;
        decryptBtn.innerHTML = '<i class="fas fa-unlock mr-2"></i> Decrypt & Verify';
    };
});
