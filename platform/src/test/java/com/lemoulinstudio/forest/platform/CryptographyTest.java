package com.lemoulinstudio.forest.platform;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.Security;
import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class CryptographyTest extends TestCase {

  public static Test suite() {
    return new TestSuite(CryptographyTest.class);
  }

  public CryptographyTest(String testName) {
    super(testName);
  }

  public void testKeyPairExportImport() throws Exception {
    Security.addProvider(new BouncyCastleProvider());

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
    
    // The private keys should be equal.
    assertTrue(originalAliceKeyPair.getPrivate().equals(importedAliceKeyPair.getPrivate()));
    
    // The public keys should be equal.
    assertTrue(originalAliceKeyPair.getPublic().equals(importedAliceKeyPair.getPublic()));
  }
  
  public void testPublicKeyExportImport() throws Exception {
    Security.addProvider(new BouncyCastleProvider());

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
    
    // The public keys should be equal.
    assertTrue(originalAlicePublicKey.equals(importedAlicePublicKey));
    
    // Prints the keys.
    //KeyExporter.exportPublicKey(originalAlicePublicKey, System.out, true);
    //KeyExporter.exportPublicKey(importedAlicePublicKey, System.out, true);
  }
}
