/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
*/

// React and ReactDOM are loaded from a CDN and available globally.
// QRCode is loaded from a CDN and available globally.
declare const QRCode: any;
declare const React: any;
declare const ReactDOM: any;

// --- Crypto Helper Functions ---
const PBKDF2_ITERATIONS = 100000;
const SALT_LENGTH_BYTES = 16;
const IV_LENGTH_BYTES = 16; // 128 bits, as requested

// Helper to convert ArrayBuffer to Base64
const arrayBufferToBase64 = (buffer: ArrayBuffer): string => {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    const len = bytes.byteLength;
    for (let i = 0; i < len; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
};

// Helper to convert Base64 to ArrayBuffer
const base64ToArrayBuffer = (base64: string): ArrayBuffer => {
    const binary_string = window.atob(base64);
    const len = binary_string.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        bytes[i] = binary_string.charCodeAt(i);
    }
    return bytes.buffer;
};

// Derives a key from a password and salt using PBKDF2
const getKey = async (password: string, salt: Uint8Array): Promise<CryptoKey> => {
    const enc = new TextEncoder();
    const keyMaterial = await window.crypto.subtle.importKey(
        'raw',
        enc.encode(password),
        { name: 'PBKDF2' },
        false,
        ['deriveKey']
    );
    return window.crypto.subtle.deriveKey(
        {
            name: 'PBKDF2',
            salt: salt,
            iterations: PBKDF2_ITERATIONS,
            hash: 'SHA-256',
        },
        keyMaterial,
        { name: 'AES-CBC', length: 256 },
        true,
        ['encrypt', 'decrypt']
    );
};

// --- React Component ---

const App = () => {
    // Encryption state
    const [plainText, setPlainText] = React.useState('');
    const [encPassword, setEncPassword] = React.useState('');
    const [cipherText, setCipherText] = React.useState('');
    const [qrCodeUrl, setQrCodeUrl] = React.useState('');
    const [isEncrypting, setIsEncrypting] = React.useState(false);

    // Decryption state
    const [cipherTextForDecrypt, setCipherTextForDecrypt] = React.useState('');
    const [decPassword, setDecPassword] = React.useState('');
    const [verificationCode, setVerificationCode] = React.useState('');
    const [decryptedText, setDecryptedText] = React.useState('');
    const [isDecrypting, setIsDecrypting] = React.useState(false);
    
    // Global error
    const [error, setError] = React.useState('');

    const handleEncrypt = async () => {
        if (!plainText || !encPassword) {
            setError('Please provide text and a password to encrypt.');
            return;
        }
        setError('');
        setIsEncrypting(true);
        setQrCodeUrl('');
        setCipherText('');

        try {
            const salt = window.crypto.getRandomValues(new Uint8Array(SALT_LENGTH_BYTES));
            const iv = window.crypto.getRandomValues(new Uint8Array(IV_LENGTH_BYTES));
            const key = await getKey(encPassword, salt);
            
            const encodedText = new TextEncoder().encode(plainText);
            const encryptedContent = await window.crypto.subtle.encrypt(
                { name: 'AES-CBC', iv: iv },
                key,
                encodedText
            );

            const combinedBuffer = new Uint8Array(salt.length + encryptedContent.byteLength);
            combinedBuffer.set(salt, 0);
            combinedBuffer.set(new Uint8Array(encryptedContent), salt.length);

            const base64CipherText = arrayBufferToBase64(combinedBuffer.buffer);
            setCipherText(base64CipherText);

            const base64VerificationCode = arrayBufferToBase64(iv.buffer);
            // QRCode is available globally from the script tag
            const qrUrl = await QRCode.toDataURL(base64VerificationCode, { errorCorrectionLevel: 'H' });
            setQrCodeUrl(qrUrl);

        } catch (e) {
            console.error(e);
            setError('Encryption failed. Please try again.');
        } finally {
            setIsEncrypting(false);
        }
    };

    const handleDecrypt = async () => {
        if (!cipherTextForDecrypt || !decPassword || !verificationCode) {
            setError('Please provide ciphertext, password, and verification code.');
            return;
        }
        setError('');
        setIsDecrypting(true);
        setDecryptedText('');

        try {
            const iv = base64ToArrayBuffer(verificationCode);
            const combinedBuffer = base64ToArrayBuffer(cipherTextForDecrypt);
            
            const salt = combinedBuffer.slice(0, SALT_LENGTH_BYTES);
            const encryptedContent = combinedBuffer.slice(SALT_LENGTH_BYTES);

            const key = await getKey(decPassword, new Uint8Array(salt));

            const decryptedContent = await window.crypto.subtle.decrypt(
                { name: 'AES-CBC', iv: new Uint8Array(iv) },
                key,
                encryptedContent
            );

            const decodedText = new TextDecoder().decode(decryptedContent);
            setDecryptedText(decodedText);
        } catch (e) {
            console.error(e);
            setError('Decryption failed. Please check your inputs (ciphertext, password, and verification code).');
        } finally {
            setIsDecrypting(false);
        }
    };
    
    const copyToClipboard = (text: string) => {
        navigator.clipboard.writeText(text).catch(err => {
            console.error('Failed to copy text: ', err);
        });
    };

    return (
        <div className="container">
            <header>
                <h1>CryptQR</h1>
                <p>Securely encrypt your text and generate a QR verification code.</p>
            </header>

            <div className="main-content">
                {/* Encryption Panel */}
                <section className="panel" aria-labelledby="encrypt-heading">
                    <h2 id="encrypt-heading">Encrypt Text</h2>
                    <div className="form-group">
                        <label htmlFor="plainText">Your Text</label>
                        <textarea
                            id="plainText"
                            className="textarea"
                            value={plainText}
                            onChange={(e) => setPlainText(e.target.value)}
                            placeholder="Enter the text you want to encrypt..."
                            aria-required="true"
                        />
                    </div>
                    <div className="form-group">
                        <label htmlFor="encPassword">Password</label>
                        <input
                            id="encPassword"
                            type="password"
                            className="input"
                            value={encPassword}
                            onChange={(e) => setEncPassword(e.target.value)}
                            placeholder="Create a strong password"
                            aria-required="true"
                        />
                    </div>
                    <button onClick={handleEncrypt} className="button" disabled={isEncrypting}>
                        {isEncrypting ? 'Encrypting...' : 'Encrypt & Generate QR'}
                    </button>
                    {cipherText && (
                        <div className="output-area">
                            <h3>Ciphertext (Encrypted Data)</h3>
                            <div className="result-box">
                                <textarea className="textarea" value={cipherText} readOnly aria-label="Ciphertext" />
                                <button onClick={() => copyToClipboard(cipherText)} className="copy-button" aria-label="Copy Ciphertext">Copy</button>
                            </div>
                        </div>
                    )}
                    {qrCodeUrl && (
                        <div className="output-area">
                            <h3>Verification Code (QR)</h3>
                            <p className="description">Scan this with a QR reader to get your verification code for decryption.</p>
                            <div className="qr-code-container">
                                <img src={qrCodeUrl} alt="QR Code containing the verification key" />
                            </div>
                        </div>
                    )}
                </section>

                {/* Decryption Panel */}
                <section className="panel" aria-labelledby="decrypt-heading">
                    <h2 id="decrypt-heading">Decrypt Text</h2>
                    <div className="form-group">
                        <label htmlFor="cipherTextForDecrypt">Ciphertext</label>
                         <textarea
                            id="cipherTextForDecrypt"
                            className="textarea"
                            value={cipherTextForDecrypt}
                            onChange={(e) => setCipherTextForDecrypt(e.target.value)}
                            placeholder="Paste the encrypted ciphertext here"
                            aria-required="true"
                        />
                    </div>
                     <div className="form-group">
                        <label htmlFor="decPassword">Password</label>
                        <input
                            id="decPassword"
                            type="password"
                            className="input"
                            value={decPassword}
                            onChange={(e) => setDecPassword(e.target.value)}
                            placeholder="Enter the password used for encryption"
                            aria-required="true"
                        />
                    </div>
                    <div className="form-group">
                        <label htmlFor="verificationCode">Verification Code (from QR)</label>
                        <input
                            id="verificationCode"
                            type="text"
                            className="input"
                            value={verificationCode}
                            onChange={(e) => setVerificationCode(e.target.value)}
                            placeholder="Enter the code from the QR scan"
                            aria-required="true"
                        />
                    </div>
                    <button onClick={handleDecrypt} className="button" disabled={isDecrypting}>
                        {isDecrypting ? 'Decrypting...' : 'Decrypt'}
                    </button>
                    {decryptedText && (
                        <div className="output-area">
                            <h3>Decrypted Text</h3>
                             <div className="result-box">
                                <textarea className="textarea" value={decryptedText} readOnly aria-label="Decrypted Text" />
                                <button onClick={() => copyToClipboard(decryptedText)} className="copy-button" aria-label="Copy Decrypted Text">Copy</button>
                            </div>
                        </div>
                    )}
                </section>
            </div>
            {error && <p className="error-message" role="alert">{error}</p>}
        </div>
    );
};

const container = document.getElementById('root');
if (container) {
    const root = ReactDOM.createRoot(container);
    root.render(<App />);
}
