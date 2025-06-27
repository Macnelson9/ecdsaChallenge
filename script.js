'use strict';

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

// Generate Key Pair
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

// Generate Address
const genAddress = function (e) {
  e.preventDefault();

  const addressHash = CryptoJS.SHA256(publicKey).toString();

  addressField.textContent = addressHash;
};

genAddressBtn.addEventListener('click', genAddress);

// Sign the message
const signMessage = function () {
  const messageVal = message.value;
  const messageHash = CryptoJS.SHA256(messageVal).toString();
  console.log(messageHash);
  verifyMessage.textContent = messageVal;

  const signature = keyPair.sign(messageHash);
  console.log(signature);

  const signatureHex = signature.toDER('hex');
  console.log(signatureHex);

  signedSignature.textContent = signatureHex;
  signatureInput.value = signatureHex;
  publicKeyInput.value = publicKey.textContent;

  const signedTransaction = {
    data: messageVal,
    signature: signatureHex,
  };
  console.log(signedTransaction);

  return messageVal, messageHash, signatureHex, signedTransaction;
};

signMessageBtn.addEventListener('click', signMessage);

// Verify the message
const verifySignedMessage = function (e) {
  e.preventDefault();

  const verifyMessageVal = verifyMessage.textContent;
  const verifyMessageHash = CryptoJS.SHA256(verifyMessageVal).toString();

  // Derive public key
  const DerivedPublicKey = ec.keyFromPublic(publicKeyInput.value, 'hex');
  console.log(DerivedPublicKey);

  const verifyDigitalSignature = DerivedPublicKey.verify(
    verifyMessageHash,
    signedSignature.textContent
  );

  console.log(verifyDigitalSignature);

  if (verifyDigitalSignature === true) {
    console.log('It is a match!!!');
    verificationResult.textContent = 'Signature Verified Successfully!!';
  } else {
    console.log('It is NOT a match!!!');
    verificationResult.textContent = 'Signature Not Verified!!';
  }
};

verifySignatureBtn.addEventListener('click', verifySignedMessage);
