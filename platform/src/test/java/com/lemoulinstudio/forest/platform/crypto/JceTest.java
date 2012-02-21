package com.lemoulinstudio.forest.platform.crypto;

import java.io.ByteArrayOutputStream;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.DHGenParameterSpec;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import static org.junit.Assert.*;
import org.junit.BeforeClass;
import org.junit.Test;

public class JceTest {
  
  public static final String famousQuote  =
          "Those who would give up Essential Liberty to purchase "
          + "a little Temporary Safety, "
          + "deserve neither Liberty nor Safety. "
          + "-- Benjamin Franklin";
  
  public final int userKeysize = 1024;
  
  public final String jceProviderName = "BC";
  
  @BeforeClass
  public static void setupBouncyCastle() {
    // Registers Bouncy Castle as a provider for JCE.
    Security.addProvider(new BouncyCastleProvider());
  }
  
  private void testCipher(String cipherName, Key encryptionKey, Key decryptionKey) throws Exception {
    // Let's define a data.
    byte[] dataToEncrypt = famousQuote.getBytes("UTF-8");
    
    // Prepare the objects to encrypt the data.
    ByteArrayOutputStream encryptedOutputStream = new ByteArrayOutputStream();
    Cipher encryptCipher = Cipher.getInstance(cipherName, jceProviderName);
    encryptCipher.init(Cipher.ENCRYPT_MODE, encryptionKey);
    
    // Encrypt the data.
    CipherOutputStream encryptionOutputStream = new CipherOutputStream(encryptedOutputStream, encryptCipher);
    encryptionOutputStream.write(dataToEncrypt);
    encryptionOutputStream.close();
    
    byte[] encryptedData = encryptedOutputStream.toByteArray();
    
    // Prepare the objects to decrypt the data.
    ByteArrayOutputStream decryptedOutputStream = new ByteArrayOutputStream();
    Cipher decryptCipher = Cipher.getInstance(cipherName, jceProviderName);
    decryptCipher.init(Cipher.DECRYPT_MODE, decryptionKey);
    
    // Decrypt the data.
    CipherOutputStream decryptionOutputStream = new CipherOutputStream(decryptedOutputStream, decryptCipher);
    decryptionOutputStream.write(encryptedData);
    decryptionOutputStream.close();
    
    byte[] decryptedData = decryptedOutputStream.toByteArray();
    
    assertTrue("The data should not be the same after encryption.",
            !Arrays.equals(dataToEncrypt, Arrays.copyOfRange(encryptedData, 0, dataToEncrypt.length)));
    
    assertArrayEquals("The data should be the same before encryption and after decryption.",
            dataToEncrypt,
            decryptedData);
    
    // Prints the data and its encrypted form.
    //System.out.println("dataToEncrypt (" + dataToEncrypt.length + ") = " + Arrays.toString(dataToEncrypt));
    //System.out.println("encryptedData (" + encryptedData.length + ") = " + Arrays.toString(encryptedData));
  }
  
  private void testSymmetricCipher(String cipherName, int keySizeInBits) throws Exception {
    // Let's choose a random encryption/decryption key.
    byte[] secretKey = new byte[keySizeInBits / 8];
    new SecureRandom().nextBytes(secretKey);
    SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey, cipherName);
    
    testCipher(cipherName, secretKeySpec, secretKeySpec);
  }

  private void testAsymmetricCipher(String cipherName, int keySizeInBits) throws Exception {
    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(cipherName, jceProviderName);
    keyPairGenerator.initialize(keySizeInBits);
    KeyPair keyPair = keyPairGenerator.generateKeyPair();
    
    testCipher(cipherName, keyPair.getPublic(), keyPair.getPrivate());
  }

  @Test
  public void testCiphers() throws Exception {
    testSymmetricCipher("AES",   256); // keysizes in bits: 128, 192, 256.
    testSymmetricCipher("CAST5", 128); // keysizes in bits: 40, 64, 80, 128.
    testSymmetricCipher("CAST6", 256); // keysizes in bits: 128, 160, 192, 224, 256.
    
    testAsymmetricCipher("RSA",  2048); // keysizes in bits: any (commonly 1024, 2048, 4096)
  }
  
  public void testSignature(String cipherName, int keySizeInBits, String hashName) throws Exception {
    // Let's define a data.
    byte[] dataToSign = famousQuote.getBytes("UTF-8");
    
    // Creates a key pair.
    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(cipherName, jceProviderName);
    keyPairGenerator.initialize(keySizeInBits);
    KeyPair keyPair = keyPairGenerator.generateKeyPair();
    
    // Creates a hash of the data.
    MessageDigest messageDigest = MessageDigest.getInstance(hashName, jceProviderName);
    messageDigest.update(dataToSign);
    byte[] dataHash = messageDigest.digest();
    
    // Prepare the objects to sign the hash.
    ByteArrayOutputStream decryptedOutputStream = new ByteArrayOutputStream();
    Cipher decryptCipher = Cipher.getInstance(cipherName, jceProviderName);
    decryptCipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
    
    // Sign the hash.
    CipherOutputStream decryptionOutputStream = new CipherOutputStream(decryptedOutputStream, decryptCipher);
    decryptionOutputStream.write(dataHash);
    decryptionOutputStream.close();
    
    byte[] signature = decryptedOutputStream.toByteArray();
    
    assertTrue("The hash and the data should not be the same.",
            !Arrays.equals(dataHash, signature));
    
    // Prepare the objects to encrypt the signature.
    ByteArrayOutputStream encryptedOutputStream = new ByteArrayOutputStream();
    Cipher encryptCipher = Cipher.getInstance(cipherName, jceProviderName);
    encryptCipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
    
    // Verify the signature.
    CipherOutputStream encryptionOutputStream = new CipherOutputStream(encryptedOutputStream, encryptCipher);
    encryptionOutputStream.write(signature);
    encryptionOutputStream.close();
    
    byte[] encryptedSignature = encryptedOutputStream.toByteArray();
    byte[] trimmedEncryptedSignature = Arrays.copyOfRange(
            encryptedSignature,
            encryptedSignature.length - dataHash.length,
            encryptedSignature.length);
    
    //System.out.println("dataHash (" + dataHash.length + ") = " + Arrays.toString(dataHash));
    //System.out.println("signature (" + signature.length + ") = " + Arrays.toString(signature));
    //System.out.println("encryptedSignature (" + encryptedSignature.length + ") = " + Arrays.toString(encryptedSignature));
    //System.out.println("trimmedEncryptedSignature (" + trimmedEncryptedSignature.length + ") = " + Arrays.toString(trimmedEncryptedSignature));
    
    assertArrayEquals("The signature's verification failed.", dataHash, trimmedEncryptedSignature);
  }
  
  @Test
  public void testSignatures() throws Exception {
    testSignature("RSA", 1024, "SHA-256");
  }
  
  public void testSharedSecret(String keyAgreementName) throws Exception {
    SecureRandom secureRandom = new SecureRandom();

    // Generate parameters with a 512-bit prime modulus and a base exponent that is at most 256 bits.
    AlgorithmParameterGenerator apg = AlgorithmParameterGenerator.getInstance(keyAgreementName, jceProviderName);
    apg.init(new DHGenParameterSpec(512, 256));
    AlgorithmParameters algorithmParameters = apg.generateParameters();
    
    // Generate a DH key pair.
    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(keyAgreementName, jceProviderName);
    keyPairGenerator.initialize(algorithmParameters.getParameterSpec(DHParameterSpec.class), secureRandom);

    // Create a key pair for Alice.
    KeyPair aliceKeyPair = keyPairGenerator.generateKeyPair();
    
    // Create a key pair for Bob.
    KeyPair bobKeyPair = keyPairGenerator.generateKeyPair();
    
    // Make sure that the generator is providing 2 different keys.
    assertTrue("The key generator should provide 2 different private keys.",
            !aliceKeyPair.getPrivate().equals(bobKeyPair.getPrivate()));
    assertTrue("The key generator should provide 2 different public keys.",
            !aliceKeyPair.getPublic().equals(bobKeyPair.getPublic()));
    
    // Compute the shared secret on alice's side.
    KeyAgreement aliceKeyAgreement = KeyAgreement.getInstance(keyAgreementName, jceProviderName);
    aliceKeyAgreement.init(aliceKeyPair.getPrivate());
    aliceKeyAgreement.doPhase(bobKeyPair.getPublic(), true);
    byte[] aliceSideSecret = aliceKeyAgreement.generateSecret();
    
    // Compute the shared secret on bob's side.
    KeyAgreement bobKeyAgreement = KeyAgreement.getInstance(keyAgreementName, jceProviderName);
    bobKeyAgreement.init(bobKeyPair.getPrivate());
    bobKeyAgreement.doPhase(aliceKeyPair.getPublic(), true);
    byte[] bobSideSecret = bobKeyAgreement.generateSecret();
    
    assertArrayEquals("Shared secret should be the same on both sides.", aliceSideSecret, bobSideSecret);
    
    // Prints the parameters used by the diffie hellman algorithm.
    //System.out.println("diffieHellmanModulus = " + diffieHellmanModulus);
    //System.out.println("diffieHellmanBase    = " + diffieHellmanBase);
    
    // Prints the shared secret of each side.
    System.out.println(String.format("aliceSideSecret (%d) = %s",
            aliceSideSecret.length, Arrays.toString(aliceSideSecret)));
    System.out.println(String.format("bobSideSecret   (%d) = %s",
            bobSideSecret.length, Arrays.toString(bobSideSecret)));
  }
  
  @Test
  public void testDiffieHellman() throws Exception {
    testSharedSecret("DH");
  }
  
}
