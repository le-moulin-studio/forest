package com.lemoulinstudio.forest.platform.handshake;

import com.lemoulinstudio.forest.platform.crypto.CryptoUtil;
import com.lemoulinstudio.forest.platform.crypto.SignatureOutputStream;
import com.lemoulinstudio.forest.platform.user.Contact;
import com.lemoulinstudio.forest.platform.user.User;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.util.BigIntegers;

public class ClientSecureConnectionHandler extends SecureConnectionHandler {
  
  private byte[] mySignatureHash;

  public ClientSecureConnectionHandler(User user, Contact contact) {
    this(user, contact, new SecureRandom());
  }

  public ClientSecureConnectionHandler(User user, Contact contact, SecureRandom secureRandom) {
    super(user.getKeyPair(), secureRandom);
    this.hisPublicKey = (RSAPublicKey) contact.getPublicKey();
  }

  // TODO: Understand why one should never use the same RSA key to sign and to encrypt,
  // and rectify Forest if needed.
  public byte[] createConnectionRequest() throws Exception {
    // This is the holder of the request.
    ByteArrayOutputStream requestOutputStream = new ByteArrayOutputStream(1200);
    
    // Generates my DH key pair.
    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DH", jceProviderName);
    keyPairGenerator.initialize(dhParameterSpec, secureRandom);
    KeyPair dhKeyPair = keyPairGenerator.generateKeyPair();
    myDhPublicKey = (DHPublicKey) dhKeyPair.getPublic();
    myDhPrivateKey = (DHPrivateKey) dhKeyPair.getPrivate();
    
    // Encrypts my DH public key with the hisPublicKey.
    Cipher requestRsaCipher = Cipher.getInstance(asymmetricCipherDesc, jceProviderName);
    requestRsaCipher.init(Cipher.WRAP_MODE, hisPublicKey);
    requestOutputStream.write(requestRsaCipher.wrap(myDhPublicKey));
    
    // Creates an AES cipher using a 256 bits key derived from the DH public key.
    Cipher requestAesCipher = Cipher.getInstance(symmetricCipherDesc, jceProviderName);
    byte[] myDhPublicKeyData = BigIntegers.asUnsignedByteArray(myDhPublicKey.getY());
    byte[] requestAesKeyData = getHash(myDhPublicKeyData, 256);
    byte[] requestInitialVector = getHash(myDhPublicKeyData, 128);
    requestAesCipher.init(Cipher.ENCRYPT_MODE,
            new SecretKeySpec(requestAesKeyData, symmetricAlgorithmName),
            new IvParameterSpec(requestInitialVector));
    DataOutputStream aesOutputStream = new DataOutputStream(
            new CipherOutputStream(requestOutputStream, requestAesCipher));
    
    // Creates the timestamp.
    long timestamp = System.currentTimeMillis();
    aesOutputStream.writeLong(timestamp);

    // First 2 bytes of my public key.
    byte[] myPublicKeyShortHash = Arrays.copyOfRange(
            BigIntegers.asUnsignedByteArray(myPublicKey.getModulus()), 0, 2);
    aesOutputStream.write(myPublicKeyShortHash);

    // Create the signature.
    Signature signer = Signature.getInstance(signatureDesc, jceProviderName);
    signer.initSign(myPrivateKey);
    DataOutputStream dos = new DataOutputStream(new SignatureOutputStream(signer));
    dos.write(requestAesKeyData); // Useful to prevent the signed content to be determinist.
    dos.writeLong(timestamp);
    CryptoUtil.exportPublicKey(hisPublicKey, dos, false);
    dos.close();
    
    // Keep the hash of the signature, for a verification of the source of the response.
    byte[] mySignature = signer.sign();
    mySignatureHash = getHash(mySignature, 256);

    aesOutputStream.write(mySignature);
    aesOutputStream.close();
    
    return requestOutputStream.toByteArray();
  }

  public void handleConnectionResponse(byte[] responseData)
          throws InvalidMessage, Exception {
    ByteArrayInputStream responseInputStream = new ByteArrayInputStream(responseData);
    
    // Reads the wrapped key.
    byte[] wrappedKey = new byte[4096 / 8];
    responseInputStream.read(wrappedKey);
    
    // Unwraps it.
    Cipher responseRsaCipher = Cipher.getInstance(asymmetricCipherDesc, jceProviderName);
    responseRsaCipher.init(Cipher.UNWRAP_MODE, myPrivateKey);
    hisDhPublicKey = (DHPublicKey) responseRsaCipher.unwrap(wrappedKey, "DH", Cipher.PUBLIC_KEY);
    
    // Creates an AES cipher using a 256 bits key derived from the DH public key.
    Cipher responseAesCipher = Cipher.getInstance(symmetricCipherDesc, jceProviderName);
    byte[] hisDhPublicKeyData = BigIntegers.asUnsignedByteArray(hisDhPublicKey.getY());
    byte[] responseAesKeyData = getHash(hisDhPublicKeyData, 256);
    byte[] responseInitialVector = getHash(hisDhPublicKeyData, 128);
    responseAesCipher.init(Cipher.DECRYPT_MODE,
            new SecretKeySpec(responseAesKeyData, symmetricAlgorithmName),
            new IvParameterSpec(responseInitialVector));
    DataInputStream aesInputStream = new DataInputStream(
            new CipherInputStream(responseInputStream, responseAesCipher));
    
    // Reads the signature's hash.
    byte[] hisSignatureHash = new byte[256 / 8];
    aesInputStream.readFully(hisSignatureHash);
    
    // Ignores the remaining data, if any.
    aesInputStream.close();

    // Compare with the signature's hash that 
    if (!Arrays.equals(mySignatureHash, hisSignatureHash)) {
      throw new InvalidMessage();
    }
    
    // From here the response is considered valid.
    
    // We have enough information to compute the shared secret and to derive
    // an encryption cipher and a decryption cipher.
    createCiphersFromSharedSecret();
  }

}
