package com.lemoulinstudio.forest.platform;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

public class CryptographyTest {
  
  @Before
  public void setupBouncyCastle() {
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
}
