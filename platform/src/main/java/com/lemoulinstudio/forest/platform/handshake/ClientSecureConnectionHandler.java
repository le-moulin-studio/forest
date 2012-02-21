package com.lemoulinstudio.forest.platform.handshake;

import com.lemoulinstudio.forest.platform.crypto.CryptoUtil;
import com.lemoulinstudio.forest.platform.crypto.MessageDigestOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.util.BigIntegers;

public class ClientSecureConnectionHandler extends SecureConnectionHandler {

  public ClientSecureConnectionHandler(KeyPair ownKeyPair, PublicKey hisPublicKey) {
    super(ownKeyPair, hisPublicKey);
  }

  public byte[] createConnectionRequest() throws Exception {
    SecureRandom secureRandom = new SecureRandom();
    
    // Generates my DH key pair.
    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DH", jceProviderName);
    keyPairGenerator.initialize(dhParameterSpec, secureRandom);
    KeyPair dhKeyPair = keyPairGenerator.generateKeyPair();
    myDhPublicKey = (DHPublicKey) dhKeyPair.getPublic();
    myDhPrivateKey = (DHPrivateKey) dhKeyPair.getPrivate();
    
    // Encrypts the DH public key with the hisPublicKey.
    Cipher rsaCipher = Cipher.getInstance("RSA", jceProviderName);
    rsaCipher.init(Cipher.WRAP_MODE, hisPublicKey);
    byte[] encryptedDhPublicKey = rsaCipher.wrap(myDhPublicKey);
    
    // Derives an AES-256 key from the DH public key.
    byte[] aesKeyData = Arrays.copyOfRange(BigIntegers.asUnsignedByteArray(myDhPublicKey.getY()), 0, 256);
    
    // Creates the AES cipher.
    Cipher aesCipher = Cipher.getInstance("AES", jceProviderName);
    aesCipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(aesKeyData, "AES"));
    
    // Handshake version.
    int handshakeVersion = 0;

    // Creates the timestamp.
    long timestamp = System.nanoTime(); // Note: it loops every 292 years, but here it is not an issue.

    // First 2 bytes of my public key.
    byte[] myPublicKeyShortHash = Arrays.copyOfRange(BigIntegers.asUnsignedByteArray(myPublicKey.getPublicExponent()), 0, 2);

    // Compute my signature.
    MessageDigestOutputStream signatureOutputStream = new MessageDigestOutputStream(MessageDigest.getInstance("SHA-256", jceProviderName));
    DataOutputStream signatureDataOutputStream = new DataOutputStream(signatureOutputStream);
    signatureDataOutputStream.writeInt(encryptedDhPublicKey.length);
    signatureDataOutputStream.write(aesKeyData); // Important to prevent predictable/repeatable signature.
    signatureDataOutputStream.writeInt(handshakeVersion);
    signatureDataOutputStream.writeLong(timestamp);
    CryptoUtil.exportPublicKey(hisPublicKey, signatureDataOutputStream, false);
    signatureDataOutputStream.close();
    byte[] mySignature = signatureOutputStream.digest();
    
    // Encrypt things with AES.
    ByteArrayOutputStream aesEncryptedOutputStream = new ByteArrayOutputStream();
    DataOutputStream aesEncryptionOutputStream = new DataOutputStream(new CipherOutputStream(aesEncryptedOutputStream, aesCipher));
    aesEncryptionOutputStream.writeInt(handshakeVersion);
    aesEncryptionOutputStream.writeLong(timestamp);
    aesEncryptionOutputStream.write(myPublicKeyShortHash);
    aesEncryptionOutputStream.write(mySignature);
    aesEncryptionOutputStream.close();
    
    byte[] aesEncryptedBlock = aesEncryptedOutputStream.toByteArray();

    // Compose the request from all the pieces.
    ByteArrayOutputStream requestOutputStream = new ByteArrayOutputStream(1024);
    DataOutputStream requestDataOutputStream = new DataOutputStream(requestOutputStream);
    requestDataOutputStream.writeInt(encryptedDhPublicKey.length);
    requestDataOutputStream.write(encryptedDhPublicKey);
    requestDataOutputStream.write(aesEncryptedBlock);
    requestDataOutputStream.close();
    
    return requestOutputStream.toByteArray();
  }

  public void handleConnectionAnswer(byte[] answerData)
          throws InvalidMessage {
  }

}
