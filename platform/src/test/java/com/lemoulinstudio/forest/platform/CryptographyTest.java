package com.lemoulinstudio.forest.platform;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import static org.junit.Assert.*;
import org.junit.BeforeClass;
import org.junit.Test;

public class CryptographyTest {
  
  public static final String famousQuote  =
          "Those who would give up Essential Liberty to purchase "
          + "a little Temporary Safety, "
          + "deserve neither Liberty nor Safety. "
          + "-- Benjamin Franklin";
  
  @BeforeClass
  public static void setupBouncyCastle() {
    // Registers Bouncy Castle as a provider for JCE.
    Security.addProvider(new BouncyCastleProvider());
  }

  @Test
  public void testKeyPairExportImport() throws Exception {
    // Creates a new user.
    UserFactory userFactory = new UserFactory(1024);
    User alice = userFactory.createUser("Alice");
    KeyPair originalAliceKeyPair = alice.getKeyPair();
    
    // Exports its key pair.
    ByteArrayOutputStream secretKeyOutputStream = new ByteArrayOutputStream();
    ByteArrayOutputStream publicKeyOutputStream = new ByteArrayOutputStream();
    KeyExporter.exportKeyPair(originalAliceKeyPair,
            "my pass phrase".toCharArray(), "Alice In Wonderland",
            secretKeyOutputStream, publicKeyOutputStream, true);
    
    // Imports the key pair from the exported data.
    KeyPair importedAliceKeyPair = KeyImporter.importKeyPair(
            new ByteArrayInputStream(secretKeyOutputStream.toByteArray()),
            "my pass phrase".toCharArray(),
            true);
    
    assertEquals("The private keys should be equal.",
            originalAliceKeyPair.getPrivate(),
            importedAliceKeyPair.getPrivate());
    
    assertEquals("The public keys should be equal.",
            originalAliceKeyPair.getPublic(),
            importedAliceKeyPair.getPublic());
  }
  
  @Test
  public void testPublicKeyExportImport() throws Exception {
    // Creates a new user.
    UserFactory userFactory = new UserFactory(1024);
    User alice = userFactory.createUser("Alice");
    PublicKey originalAlicePublicKey = alice.getKeyPair().getPublic();
    
    // Exports its public key.
    ByteArrayOutputStream publicKeyOutputStream = new ByteArrayOutputStream();
    KeyExporter.exportPublicKey(originalAlicePublicKey, publicKeyOutputStream, true);
    
    // Imports the public key from the exported data.
    PublicKey importedAlicePublicKey = KeyImporter.importPublicKey(
            new ByteArrayInputStream(publicKeyOutputStream.toByteArray()),
            true);
    
    assertEquals("The public keys should be equal.",
            originalAlicePublicKey,
            importedAlicePublicKey);
    
    // Prints the keys.
    //KeyExporter.exportPublicKey(originalAlicePublicKey, System.out, true);
    //KeyExporter.exportPublicKey(importedAlicePublicKey, System.out, true);
  }
  
  @Test
  public void testAesEncryptionDecryption() throws Exception {
    // Let's define a data.
    byte[] dataToEncrypt = famousQuote.getBytes();
    
    // Let's choose a random encryption/decryption key.
    byte[] secretKey = new byte[256 / 8];
    new SecureRandom().nextBytes(secretKey);
    
    // Prepare the objects to encrypt the data.
    PaddedBufferedBlockCipher encryptCipher = new PaddedBufferedBlockCipher(new AESEngine());
    encryptCipher.init(true, new KeyParameter(secretKey));
    byte[] encryptedData = new byte[dataToEncrypt.length + encryptCipher.getBlockSize() * 2];
    
    // Encrypt the data.
    int nbEncryptedBytes = encryptCipher.processBytes(dataToEncrypt, 0, dataToEncrypt.length, encryptedData, 0);
    nbEncryptedBytes += encryptCipher.doFinal(encryptedData, nbEncryptedBytes);
    
    // Prepare the objects to decrypt the data.
    PaddedBufferedBlockCipher decryptCipher = new PaddedBufferedBlockCipher(new AESEngine());
    decryptCipher.init(false, new KeyParameter(secretKey));
    byte[] decryptedData = new byte[dataToEncrypt.length];
    
    // Decrypt the data.
    int nbDecryptedBytes = decryptCipher.processBytes(encryptedData, 0, nbEncryptedBytes, decryptedData, 0);
    nbDecryptedBytes += decryptCipher.doFinal(decryptedData, nbDecryptedBytes);
    
    assertEquals("The decrypted data should have the same size that the original one.",
            dataToEncrypt.length,
            nbDecryptedBytes);
    
    assertArrayEquals("The data should be the same before encryption and after decryption.",
            dataToEncrypt,
            decryptedData);
  }
  
}
