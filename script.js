'use strict';

// Initialize the elliptic curve
const EC = elliptic.ec;

// Choosing a curve on the EC
const ec = new EC('secp256k1');

// Generate Key Pair
let keyPair;

// Buttons
const genKeyPairBtn = document.getElementById('keyPairBtn');
const genAddressBtn = document.getElementById('genAddressBtn');
const signMessageBtn = document.getElementById('signMessage');
const verifySignatureBtn = document.getElementById('verifySignature');

// Fields and Inputs
const privateKeyField = document.getElementById('privateKey');
const publicKeyField = document.getElementById('publicKey');
const addressField = document.getElementById('addressField');
const message = document.getElementById('message');
const verifyMessage = document.getElementById('verifyMessage');
const signedSignature = document.getElementById('signature');
const signatureInput = document.getElementById('signatureInput');
const publicKeyInput = document.getElementById('publicKeyInput');
const verificationResult = document.getElementById('verificationResult');

// Generate Key Pair function
const genKeyPair = function (e) {
  e.preventDefault();
  keyPair = ec.genKeyPair();

  // Access the private key
  const privateKey = keyPair.getPrivate('hex');

  // Access the public key
  const publicKey = keyPair.getPublic('hex');

  privateKeyField.textContent = privateKey;
  publicKeyField.textContent = publicKey;

  return publicKey, privateKey;
};

genKeyPairBtn.addEventListener('click', genKeyPair);

// Generate Address function
const genAddress = function (e) {
  e.preventDefault();

  const addressHash = CryptoJS.SHA256(publicKey).toString();

  addressField.textContent = addressHash;
};

genAddressBtn.addEventListener('click', genAddress);

// Sign the message function
const signMessage = function (e) {
  try {
    e.preventDefault();

    const messageVal = message.value;
    if (!messageVal) alert('Please enter a message to sign');

    // Hash the message
    const messageHash = CryptoJS.SHA256(messageVal).toString();

    verifyMessage.textContent = messageVal;

    // Sign the message hash with private key + ECDSA
    const signature = keyPair.sign(messageHash);

    // Providing the signature in hexadecimal
    const signatureHex = signature.toDER('hex');

    signedSignature.textContent = signatureHex;
    signatureInput.value = signatureHex;
    publicKeyInput.value = publicKey.textContent;

    // Creating the signed transaction object to be sent for verification
    const signedTransaction = {
      data: messageVal,
      signature: signatureHex,
    };

    return messageVal, messageHash, signatureHex, signedTransaction;
  } catch (err) {
    alert(`Sorry, ${err} error has occurred. Please fill in the fields`);
  }
};

signMessageBtn.addEventListener('click', signMessage);

// Verify the message function
const verifySignedMessage = function (e) {
  try {
    e.preventDefault();

    // Check for empty fields
    if (
      !verifyMessage.textContent ||
      !signatureInput.value ||
      !publicKeyInput.value
    ) {
      alert('Please fill in all fields before verifying the signature.');
      verificationResult.textContent = 'Signature Not Verified!';
      return;
    }

    const verifyMessageVal = verifyMessage.textContent;

    // Reconstructed Message Hash
    const verifyMessageHash = CryptoJS.SHA256(verifyMessageVal).toString();

    // Derive public key
    const DerivedPublicKey = ec.keyFromPublic(publicKeyInput.value, 'hex');

    // Verify Digital Signature
    const verifyDigitalSignature = DerivedPublicKey.verify(
      verifyMessageHash,
      signedSignature.textContent
    );

    if (verifyDigitalSignature === true) {
      verificationResult.textContent = 'Signature Verified Successfully!!';
    } else {
      verificationResult.textContent = 'Signature Not Verified!!';
    }
  } catch (err) {
    alert(`An ${err} has occurred.`);
  }
};

verifySignatureBtn.addEventListener('click', verifySignedMessage);
