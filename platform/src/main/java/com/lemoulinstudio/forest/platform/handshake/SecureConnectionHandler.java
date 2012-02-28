package com.lemoulinstudio.forest.platform.handshake;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

// TODO: Garbage-collect this object after the handshake is over.
public class SecureConnectionHandler {
  
  protected static final String jceProviderName        = "BC";
  
  protected static final String asymmetricCipherDesc   = "RSA/NONE/OAEPPADDING";
  
  protected static final String symmetricAlgorithmName = "AES";
  protected static final String symmetricCipherDesc    = "AES/GCM/NOPADDING";
  
  protected static final String signatureDesc          = "SHA256withRSA/PSS";
  
  // TODO: choose some definite parameters later.
  public static final DHParameterSpec dhParameterSpec = new DHParameterSpec(
          new BigInteger(new byte[] {0, -83, -124, 30, 89, 71, -54, 121, -84, -119, 46, 51, 105, -13, 0, -82, 62, 127, 5, -109, -123, 12, -62, 72, 88, -86, -87, -110, -76, -79, -85, -103, -61, 8, -28, 63, -64, 92, 70, -35, -14, -28, -30, -48, 106, -51, 7, -58, 98, -68, 104, 74, -86, 60, 65, -68, -93, 111, -26, 67, -26, -113, 29, 2, -13, 99, -43, 84, -91, 92, -54, -32, -24, 3, 34, -61, 110, -3, 8, 28, 37, 45, 94, -23, 60, -117, -79, -82, 91, -32, 9, -117, 121, 123, -68, 25, 36, -107, -90, -115, -122, -92, -101, 6, 127, 23, 100, 5, 83, -102, 24, 58, -101, 66, -30, -66, 106, 1, -45, 111, -65, -68, -7, -119, 49, -115, 51, -5, -9}),
          new BigInteger(new byte[] {0, 109, -24, -113, 114, 118, -119, 114, -73, -35, -1, 28, -10, 41, -8, 10, 22, -89, 116, 61, -72, -101, 5, 83, -3, -99, 37, -43, -115, -28, -72, -45, -91, -99, -113, 27, 18, 102, -10, -24, 18, -44, 1, 56, 3, 75, -86, -33, -103, -39, -104, -90, 102, -96, 77, -6, 107, -49, -38, -108, 89, 51, -109, 4, 30, -31, 15, -88, 48, -128, -27, 46, 71, -97, -52, -30, -128, -122, 47, -51, 9, 13, -85, 85, 3, 23, 17, -113, -48, -66, -24, 8, -73, 71, -3, -120, -84, -50, -43, 71, 92, 2, 0, -18, 78, 30, -109, -69, -107, -114, 92, -67, 35, -50, 74, -36, -59, 26, -2, 113, 46, 106, -86, -39, -38, -106, -1, 57, 126}),
          1000);
  
  protected SecureRandom secureRandom;
  
  protected RSAPublicKey  myPublicKey;
  protected RSAPrivateKey myPrivateKey;
  protected RSAPublicKey  hisPublicKey;
  
  protected DHPublicKey  myDhPublicKey;
  protected DHPrivateKey myDhPrivateKey;
  protected DHPublicKey  hisDhPublicKey;
  
  private Cipher encryptionCipher;
  private Cipher decryptionCipher;

  public SecureConnectionHandler(KeyPair myRsaKeyPair, SecureRandom secureRandom) {
    this.myPublicKey  = (RSAPublicKey)  myRsaKeyPair.getPublic();
    this.myPrivateKey = (RSAPrivateKey) myRsaKeyPair.getPrivate();
    this.secureRandom = secureRandom;
  }
  
  
  // TODO: bad practice? choose only one algorithm instead?
  protected byte[] getHash(byte[] data, int hashSizeInBits) {
    String digestAlgoName;
    switch (hashSizeInBits) {
      case 128: digestAlgoName = "MD5"; break;
      case 160: digestAlgoName = "SHA-1"; break;
      case 224: digestAlgoName = "SHA-224"; break;
      case 256: digestAlgoName = "SHA-256"; break;
      case 384: digestAlgoName = "SHA-384"; break;
      case 512: digestAlgoName = "SHA-512"; break;
      default: throw new IllegalArgumentException("Unsupported hash size (in bits).");
    }
      
    try {
      MessageDigest digest = MessageDigest.getInstance(digestAlgoName, jceProviderName);
      digest.update(data);
      return digest.digest();
    } catch (GeneralSecurityException ex) {
      throw new Error("Human Error");
    }
  }

  protected void createCiphersFromSharedSecret()
          throws IllegalStateException, GeneralSecurityException, InvalidKeyException {
    // Compute the shared secret.
    KeyAgreement diffieHellmanKeyAgreement = KeyAgreement.getInstance("DH", jceProviderName);
    diffieHellmanKeyAgreement.init(myDhPrivateKey);
    diffieHellmanKeyAgreement.doPhase(hisDhPublicKey, true);
    byte[] sharedSecret = diffieHellmanKeyAgreement.generateSecret();
    
    // Derives an AES-256 key from the shared secret.
    byte[] aesKeyData = getHash(sharedSecret, 256);
    SecretKeySpec aesKeySpec = new SecretKeySpec(aesKeyData, symmetricAlgorithmName);
    byte[] initialVector = getHash(sharedSecret, 128);
    IvParameterSpec ivParameterSpec = new IvParameterSpec(initialVector);
    
    // Creates the encryption cipher.
    encryptionCipher = Cipher.getInstance(symmetricCipherDesc, jceProviderName);
    encryptionCipher.init(Cipher.ENCRYPT_MODE, aesKeySpec, ivParameterSpec);
    
    // Creates the decryption cipher.
    decryptionCipher = Cipher.getInstance(symmetricCipherDesc, jceProviderName);
    decryptionCipher.init(Cipher.DECRYPT_MODE, aesKeySpec, ivParameterSpec);
  }
  
  public Cipher getEncryptionCipher() {
    return encryptionCipher;
  }

  public Cipher getDecryptionCipher() {
    return decryptionCipher;
  }
  
}
