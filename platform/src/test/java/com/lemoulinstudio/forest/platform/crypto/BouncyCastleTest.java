package com.lemoulinstudio.forest.platform.crypto;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.agreement.DHBasicAgreement;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.AESFastEngine;
import org.bouncycastle.crypto.engines.AESLightEngine;
import org.bouncycastle.crypto.engines.CAST5Engine;
import org.bouncycastle.crypto.engines.CAST6Engine;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.generators.DHKeyPairGenerator;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.DHKeyGenerationParameters;
import org.bouncycastle.crypto.params.DHParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.provider.JCERSAPrivateCrtKey;
import org.bouncycastle.jce.provider.JCERSAPublicKey;
import static org.junit.Assert.*;
import org.junit.BeforeClass;
import org.junit.Test;

public class BouncyCastleTest {
  
  public static final String famousQuote  =
          "Those who would give up Essential Liberty to purchase "
          + "a little Temporary Safety, "
          + "deserve neither Liberty nor Safety. "
          + "-- Benjamin Franklin";
  
  public final int rsaKeysize = 1024;
  
  @BeforeClass
  public static void setupBouncyCastle() {
    // Registers Bouncy Castle as a provider for JCE.
    Security.addProvider(new BouncyCastleProvider());
  }
  
  private void testBlockCipher(
          BlockCipher encryptEngine,
          BlockCipher decryptEngine,
          int keySizeInBits) throws Exception {
    // Let's define a data.
    byte[] dataToEncrypt = famousQuote.getBytes("UTF-8");
    
    // Let's choose a random encryption/decryption key.
    byte[] secretKey = new byte[keySizeInBits / 8];
    new SecureRandom().nextBytes(secretKey);
    
    // Prepare the objects to encrypt the data.
    PaddedBufferedBlockCipher encryptCipher = new PaddedBufferedBlockCipher(encryptEngine);
    encryptCipher.init(true, new KeyParameter(secretKey));
    byte[] encryptedData = new byte[dataToEncrypt.length + encryptCipher.getBlockSize() * 2];
    
    // Encrypt the data.
    int nbEncryptedBytes = encryptCipher.processBytes(dataToEncrypt, 0, dataToEncrypt.length, encryptedData, 0);
    nbEncryptedBytes += encryptCipher.doFinal(encryptedData, nbEncryptedBytes);
    
    // Prepare the objects to decrypt the data.
    PaddedBufferedBlockCipher decryptCipher = new PaddedBufferedBlockCipher(decryptEngine);
    decryptCipher.init(false, new KeyParameter(secretKey));
    byte[] decryptedData = new byte[dataToEncrypt.length];
    
    // Decrypt the data.
    int nbDecryptedBytes = decryptCipher.processBytes(encryptedData, 0, nbEncryptedBytes, decryptedData, 0);
    nbDecryptedBytes += decryptCipher.doFinal(decryptedData, nbDecryptedBytes);
    
    assertTrue("The data should not be the same after encryption.",
            !Arrays.equals(dataToEncrypt, Arrays.copyOfRange(encryptedData, 0, dataToEncrypt.length)));
    
    assertEquals("The decrypted data should have the same size that the original one.",
            dataToEncrypt.length,
            nbDecryptedBytes);
    
    assertArrayEquals("The data should be the same before encryption and after decryption.",
            dataToEncrypt,
            decryptedData);
    
    // Prints the data and its encrypted form.
    //System.out.println("dataToEncrypt (" + dataToEncrypt.length * 8 + " bits) = " + Arrays.toString(dataToEncrypt));
    //System.out.println("encryptedData (" + encryptedData.length * 8 + " bits) = " + Arrays.toString(encryptedData));
  }
  
  @Test
  public void testBlockCiphers() throws Exception {
    testBlockCipher(new AESEngine(),      new AESEngine(),      256); // keysizes in bits: 128, 192, 256.
    testBlockCipher(new AESFastEngine(),  new AESFastEngine(),  256);
    testBlockCipher(new AESLightEngine(), new AESLightEngine(), 256);
    testBlockCipher(new CAST5Engine(),    new CAST5Engine(),    128); // keysizes in bits: 40, 64, 80, 128.
    testBlockCipher(new CAST6Engine(),    new CAST6Engine(),    256); // keysizes in bits: 128, 160, 192, 224, 256.
  }
  
  @Test
  public void testRSACipher() throws Exception {
    // Creates a RSA key pair.
    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
    keyPairGenerator.initialize(rsaKeysize);
    KeyPair keyPair = keyPairGenerator.generateKeyPair();
    JCERSAPublicKey publicKey = (JCERSAPublicKey) keyPair.getPublic();
    JCERSAPrivateCrtKey privateKey = (JCERSAPrivateCrtKey) keyPair.getPrivate();
    
    // Setup the encryption cipher.
    RSAEngine encryptionCipher = new RSAEngine();
    RSAKeyParameters publicKeyParameters = new RSAKeyParameters(false, publicKey.getModulus(), publicKey.getPublicExponent());
    encryptionCipher.init(true, publicKeyParameters);
    
    // Let's define a data.
    byte[] dataToEncrypt = new byte[encryptionCipher.getInputBlockSize()];
    new SecureRandom().nextBytes(dataToEncrypt);
    
    // Encrypt the data.
    byte[] encryptedData = encryptionCipher.processBlock(dataToEncrypt, 0, dataToEncrypt.length);
    
    // Setup the decryption cipher.
    RSAEngine decryptionCipher = new RSAEngine();
    RSAPrivateCrtKeyParameters privateKeyParameters = new RSAPrivateCrtKeyParameters(
            privateKey.getModulus(),
            privateKey.getPublicExponent(),
            privateKey.getPrivateExponent(),
            privateKey.getPrimeP(),
            privateKey.getPrimeQ(),
            privateKey.getPrimeExponentP(),
            privateKey.getPrimeExponentQ(),
            privateKey.getCrtCoefficient());
    decryptionCipher.init(false, privateKeyParameters);
    
    // Decrypt the data.
    byte[] decryptedData = decryptionCipher.processBlock(encryptedData, 0, encryptedData.length);
    
    assertTrue("The data should not be the same after encryption.",
            !Arrays.equals(dataToEncrypt, encryptedData));
    
    assertArrayEquals("The data should be the same before encryption and after decryption.",
            dataToEncrypt,
            decryptedData);
    
    // Prints the data and its encrypted form.
    //System.out.println("dataToEncrypt (" + dataToEncrypt.length * 8 + " bits) = " + Arrays.toString(dataToEncrypt));
    //System.out.println("encryptedData (" + encryptedData.length * 8 + " bits) = " + Arrays.toString(encryptedData));
    //System.out.println("decryptedData (" + decryptedData.length * 8 + " bits) = " + Arrays.toString(decryptedData));
  }
  
  @Test
  public void testRSASignedData() throws Exception {
    // Let's define a data.
    byte[] dataToSign = famousQuote.getBytes("UTF-8");
    
    // Creates a RSA key pair.
    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
    keyPairGenerator.initialize(rsaKeysize);
    KeyPair keyPair = keyPairGenerator.generateKeyPair();
    JCERSAPublicKey publicKey = (JCERSAPublicKey) keyPair.getPublic();
    JCERSAPrivateCrtKey privateKey = (JCERSAPrivateCrtKey) keyPair.getPrivate();
    
    // Creates a hash of the data.
    MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
    messageDigest.update(dataToSign);
    byte[] dataHash = messageDigest.digest();
    
    // Creates the signature with Alice's private key.
    RSAEngine decryptionCipher = new RSAEngine();
    RSAPrivateCrtKeyParameters privateKeyParameters = new RSAPrivateCrtKeyParameters(
            privateKey.getModulus(),
            privateKey.getPublicExponent(),
            privateKey.getPrivateExponent(),
            privateKey.getPrimeP(),
            privateKey.getPrimeQ(),
            privateKey.getPrimeExponentP(),
            privateKey.getPrimeExponentQ(),
            privateKey.getCrtCoefficient());
    decryptionCipher.init(false, privateKeyParameters);
    
    // Sign the hash.
    byte[] signature = decryptionCipher.processBlock(dataHash, 0, dataHash.length);
    
    assertTrue("The hash and the data should not be the same.",
            !Arrays.equals(dataHash, signature));
    
    // Encrypt the signature of the data with Alice's public key.
    RSAEngine encryptionCipher = new RSAEngine();
    RSAKeyParameters publicKeyParameters = new RSAKeyParameters(false, publicKey.getModulus(), publicKey.getPublicExponent());
    encryptionCipher.init(true, publicKeyParameters);
    
    // Verify the signature.
    byte[] encryptedSignature = encryptionCipher.processBlock(signature, 0, signature.length);
    byte[] trimmedEncryptedSignature = Arrays.copyOfRange(
            encryptedSignature,
            encryptedSignature.length - dataHash.length,
            encryptedSignature.length);
    
    //System.out.println("dataHash (" + dataHash.length * 8 + " bits) = " + Arrays.toString(dataHash));
    //System.out.println("signature (" + signature.length * 8 + " bits) = " + Arrays.toString(signature));
    //System.out.println("encryptedSignature (" + encryptedSignature.length * 8 + " bits) = " + Arrays.toString(encryptedSignature));
    //System.out.println("trimmedEncryptedSignature (" + trimmedEncryptedSignature.length * 8 + " bits) = " + Arrays.toString(trimmedEncryptedSignature));
    
    assertArrayEquals("The signature's verification failed.", dataHash, trimmedEncryptedSignature);
  }
  
  @Test
  public void testDiffieHellmanSharedSecret() throws Exception {
    SecureRandom secureRandom = new SecureRandom();
    
    // Setup the public predefined parameters for our Diffie Hellman key exchange.
    //BigInteger diffieHellmanModulus = BigInteger.probablePrime(4096, secureRandom);
    //BigInteger diffieHellmanBase = BigInteger.probablePrime(1024, secureRandom);
    BigInteger diffieHellmanModulus = BigInteger.probablePrime(1024, secureRandom);
    BigInteger diffieHellmanBase = BigInteger.probablePrime(256, secureRandom);
    DHKeyGenerationParameters diffieHellmanKeyGenerationParameters =
            new DHKeyGenerationParameters(secureRandom,
                    new DHParameters(diffieHellmanModulus, diffieHellmanBase));
    
    // Setup a key pair generator.
    DHKeyPairGenerator diffieHellmanKeyPairGen = new DHKeyPairGenerator();
    diffieHellmanKeyPairGen.init(diffieHellmanKeyGenerationParameters);
    
    // Create a key pair for Alice.
    AsymmetricCipherKeyPair aliceKeyPair = diffieHellmanKeyPairGen.generateKeyPair();
    
    // Create a key pair for Bob.
    AsymmetricCipherKeyPair bobKeyPair = diffieHellmanKeyPairGen.generateKeyPair();
    
    // Make sure that the generator is providing 2 different keys.
    assertTrue("The key generator should provide 2 different private keys.",
            !aliceKeyPair.getPrivate().equals(bobKeyPair.getPrivate()));
    assertTrue("The key generator should provide 2 different public keys.",
            !aliceKeyPair.getPublic().equals(bobKeyPair.getPublic()));
    
    // Compute the shared secret on alice's side.
    DHBasicAgreement aliceKeyAgreement = new DHBasicAgreement();
    aliceKeyAgreement.init(aliceKeyPair.getPrivate());
    BigInteger aliceSideSecret = aliceKeyAgreement.calculateAgreement(bobKeyPair.getPublic());
    
    // Compute the shared secret on bob's side.
    DHBasicAgreement bobKeyAgreement = new DHBasicAgreement();
    bobKeyAgreement.init(bobKeyPair.getPrivate());
    BigInteger bobSideSecret = bobKeyAgreement.calculateAgreement(aliceKeyPair.getPublic());
    
    assertEquals("Shared secret should be the same on both sides.", aliceSideSecret, bobSideSecret);
    
    // Prints the parameters used by the diffie hellman algorithm.
    //System.out.println("diffieHellmanModulus = " + diffieHellmanModulus);
    //System.out.println("diffieHellmanBase    = " + diffieHellmanBase);
    
    // Prints the shared secret of each side.
    //System.out.println("aliceSideSecret      = " + aliceSideSecret);
    //System.out.println("bobSideSecret        = " + bobSideSecret);
  }
  
}
