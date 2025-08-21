import React, { useState, useMemo, useEffect, useCallback } from 'react';
import { createRoot } from 'react-dom/client';
import QRCode from 'qrcode';

const App = () => {
  const [activeTab, setActiveTab] = useState('encrypt');

  // --- Encrypt State ---
  const [plaintext, setPlaintext] = useState('');
  const [encryptPassword, setEncryptPassword] = useState('');
  const [showEncryptPassword, setShowEncryptPassword] = useState(false);
  const [generatedCiphertext, setGeneratedCiphertext] = useState('');
  const [verificationCode, setVerificationCode] = useState('');
  const [isEncrypting, setIsEncrypting] = useState(false);
  const [encryptError, setEncryptError] = useState('');

  // --- Decrypt State ---
  const [ciphertext, setCiphertext] = useState('');
  const [decryptPassword, setDecryptPassword] = useState('');
  const [showDecryptPassword, setShowDecryptPassword] = useState(false);
  const [decryptVerificationCode, setDecryptVerificationCode] = useState('');
  const [decryptedPlaintext, setDecryptedPlaintext] = useState('');
  const [isDecrypting, setIsDecrypting] = useState(false);
  const [decryptError, setDecryptError] = useState('');

  // --- Crypto Helpers ---
  const textEncoder = new TextEncoder();
  const textDecoder = new TextDecoder();

  const arrayBufferToBase64 = (buffer: ArrayBuffer) => {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    const len = bytes.byteLength;
    for (let i = 0; i < len; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
  };

  const base64ToArrayBuffer = (base64: string) => {
    const binary_string = window.atob(base64);
    const len = binary_string.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
      bytes[i] = binary_string.charCodeAt(i);
    }
    return bytes.buffer;
  };
  
  const generateRandomString = (length: number) => {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    const randomValues = new Uint32Array(length);
    window.crypto.getRandomValues(randomValues);
    for (let i = 0; i < length; i++) {
      result += chars.charAt(randomValues[i] % chars.length);
    }
    return result;
  };

  const deriveKey = async (password: string, salt: string) => {
    const keyMaterial = await window.crypto.subtle.importKey(
      'raw',
      textEncoder.encode(password),
      { name: 'PBKDF2' },
      false,
      ['deriveKey']
    );
    return window.crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: textEncoder.encode(salt),
        iterations: 100000,
        hash: 'SHA-256',
      },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt']
    );
  };

  // --- Password Validation ---
  const isEncryptPasswordValid = useMemo(() => {
    return encryptPassword.length >= 4 && encryptPassword.length <= 64;
  }, [encryptPassword]);

  // --- QR Code Generation ---
  useEffect(() => {
    if (verificationCode) {
      QRCode.toCanvas(document.getElementById('qr-canvas'), verificationCode, { width: 220 }, (error: Error) => {
        if (error) console.error(error);
      });
    }
  }, [verificationCode]);

  // --- Handlers ---
  const handleEncrypt = async () => {
    if (!isEncryptPasswordValid || !plaintext) return;
    setIsEncrypting(true);
    setEncryptError('');
    setGeneratedCiphertext('');
    setVerificationCode('');

    try {
      const salt = generateRandomString(128);
      const iv = window.crypto.getRandomValues(new Uint8Array(12));
      const key = await deriveKey(encryptPassword, salt);
      
      const encrypted = await window.crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: iv },
        key,
        textEncoder.encode(plaintext)
      );

      const ciphertext = `${arrayBufferToBase64(iv)}.${arrayBufferToBase64(encrypted)}`;
      setGeneratedCiphertext(ciphertext);
      setVerificationCode(salt);
    } catch (error) {
      console.error(error);
      setEncryptError('Encryption failed. Please try again.');
    } finally {
      setIsEncrypting(false);
    }
  };

  const handleDecrypt = async () => {
    if (!decryptPassword || !ciphertext || decryptVerificationCode.length !== 128) return;
    setIsDecrypting(true);
    setDecryptError('');
    setDecryptedPlaintext('');
    
    try {
      const [ivBase64, encryptedBase64] = ciphertext.split('.');
      if (!ivBase64 || !encryptedBase64) {
        throw new Error('Invalid ciphertext format.');
      }

      const iv = base64ToArrayBuffer(ivBase64);
      const encrypted = base64ToArrayBuffer(encryptedBase64);
      const key = await deriveKey(decryptPassword, decryptVerificationCode);

      const decrypted = await window.crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: iv },
        key,
        encrypted
      );

      setDecryptedPlaintext(textDecoder.decode(decrypted));
    } catch (error) {
      console.error(error);
      setDecryptError('Decryption failed. Check your inputs and try again.');
    } finally {
      setIsDecrypting(false);
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text).catch(err => console.error("Copy failed", err));
  };

  const downloadQR = () => {
    const canvas = document.getElementById('qr-canvas') as HTMLCanvasElement;
    if(canvas) {
        const pngUrl = canvas
            .toDataURL("image/png")
            .replace("image/png", "image/octet-stream");
        let downloadLink = document.createElement("a");
        downloadLink.href = pngUrl;
        downloadLink.download = "verification-code-qr.png";
        document.body.appendChild(downloadLink);
        downloadLink.click();
        document.body.removeChild(downloadLink);
    }
  };


  const renderEncryptPanel = () => (
    <div className="panel">
      <div className="form-group">
        <label htmlFor="plaintext">Plaintext</label>
        <textarea id="plaintext" value={plaintext} onChange={(e) => setPlaintext(e.target.value)} placeholder="Enter your secret message..."></textarea>
      </div>
      <div className="form-group">
        <label htmlFor="encrypt-password">Password</label>
        <div className="password-wrapper">
          <input id="encrypt-password" type={showEncryptPassword ? 'text' : 'password'} className="input" value={encryptPassword} onChange={(e) => setEncryptPassword(e.target.value)} placeholder="Enter a strong password" />
          <button className="password-toggle" onClick={() => setShowEncryptPassword(!showEncryptPassword)} aria-label="Toggle password visibility">
            {showEncryptPassword ? '👁️' : '🔒'}
          </button>
        </div>
        <p className={`password-validation ${encryptPassword.length > 0 && !isEncryptPasswordValid ? 'invalid' : ''}`}>
          Password must be between 4 and 64 characters.
        </p>
      </div>
      <button className="btn" onClick={handleEncrypt} disabled={!plaintext || !isEncryptPasswordValid || isEncrypting}>
        {isEncrypting && <span className="loader"></span>}
        Encrypt
      </button>
      {encryptError && <p className="error-message">{encryptError}</p>}
      {generatedCiphertext && (
        <>
          <div className="output-group">
            <div className="output-header">
                <label htmlFor="generated-ciphertext">Ciphertext</label>
                <button className="btn btn-secondary" onClick={() => copyToClipboard(generatedCiphertext)}>Copy</button>
            </div>
            <textarea id="generated-ciphertext" value={generatedCiphertext} readOnly></textarea>
          </div>
          <div className="output-group">
            <div className="output-header">
                <label htmlFor="verification-code">Verification Code</label>
                <button className="btn btn-secondary" onClick={() => copyToClipboard(verificationCode)}>Copy Code</button>
            </div>
            <textarea id="verification-code" value={verificationCode} readOnly rows={3}></textarea>
            <div className="qr-container">
                <canvas id="qr-canvas"></canvas>
                <div className="qr-actions">
                    <button className="btn btn-secondary" onClick={downloadQR}>Download QR</button>
                </div>
            </div>
          </div>
        </>
      )}
    </div>
  );

  const renderDecryptPanel = () => (
    <div className="panel">
       <div className="form-group">
        <label htmlFor="ciphertext">Ciphertext</label>
        <textarea id="ciphertext" value={ciphertext} onChange={(e) => setCiphertext(e.target.value)} placeholder="Paste your encrypted message here..."></textarea>
      </div>
      <div className="form-group">
        <label htmlFor="decrypt-verification-code">128-Character Verification Code</label>
        <textarea id="decrypt-verification-code" rows={3} value={decryptVerificationCode} onChange={(e) => setDecryptVerificationCode(e.target.value)} placeholder="Enter the 128-character code from the QR code..."></textarea>
      </div>
      <div className="form-group">
        <label htmlFor="decrypt-password">Password</label>
        <div className="password-wrapper">
            <input id="decrypt-password" type={showDecryptPassword ? 'text' : 'password'} className="input" value={decryptPassword} onChange={(e) => setDecryptPassword(e.target.value)} placeholder="Enter the password" />
            <button className="password-toggle" onClick={() => setShowDecryptPassword(!showDecryptPassword)} aria-label="Toggle password visibility">
                {showDecryptPassword ? '👁️' : '🔒'}
            </button>
        </div>
      </div>
      <button className="btn" onClick={handleDecrypt} disabled={!ciphertext || !decryptPassword || decryptVerificationCode.length !== 128 || isDecrypting}>
        {isDecrypting && <span className="loader"></span>}
        Decrypt
      </button>
      {decryptError && <p className="error-message">{decryptError}</p>}
      {decryptedPlaintext && (
        <div className="output-group">
            <div className="output-header">
                <label htmlFor="decrypted-plaintext">Decrypted Plaintext</label>
                <button className="btn btn-secondary" onClick={() => copyToClipboard(decryptedPlaintext)}>Copy</button>
            </div>
            <textarea id="decrypted-plaintext" value={decryptedPlaintext} readOnly></textarea>
        </div>
      )}
    </div>
  );


  return (
    <main className="container">
      <h1>Secure Crypto Tool</h1>
      <div className="tabs">
        <button className={`tab ${activeTab === 'encrypt' ? 'active' : ''}`} onClick={() => setActiveTab('encrypt')}>
          Encrypt
        </button>
        <button className={`tab ${activeTab === 'decrypt' ? 'active' : ''}`} onClick={() => setActiveTab('decrypt')}>
          Decrypt
        </button>
      </div>
      {activeTab === 'encrypt' ? renderEncryptPanel() : renderDecryptPanel()}
    </main>
  );
};

const container = document.getElementById('root');
const root = createRoot(container!);
root.render(<App />);
