package com.lemoulinstudio.forest.platform.crypto;

import com.lemoulinstudio.forest.platform.User;
import com.lemoulinstudio.forest.platform.UserFactory;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

public class CryptoUtilTest {
  
  public static final String famousQuote  =
          "Those who would give up Essential Liberty to purchase "
          + "a little Temporary Safety, "
          + "deserve neither Liberty nor Safety. "
          + "-- Benjamin Franklin";
  
  public final int userKeysize = 1024;
  
  private UserFactory userFactory;
  
  @BeforeClass
  public static void setupBouncyCastle() {
    // Registers Bouncy Castle as a provider for JCE.
    Security.addProvider(new BouncyCastleProvider());
  }
  
  @Before
  public void perTestSetup() {
    // Setup a user factory. Users are assigned a keypair.
    userFactory = new UserFactory(userKeysize);
  }

  @Test
  public void testKeyPairExportImport() throws Exception {
    // Creates a new user.
    User alice = userFactory.createUser("Alice");
    KeyPair originalAliceKeyPair = alice.getKeyPair();
    
    // Exports its key pair.
    ByteArrayOutputStream secretKeyOutputStream = new ByteArrayOutputStream();
    ByteArrayOutputStream publicKeyOutputStream = new ByteArrayOutputStream();
    CryptoUtil.exportKeyPair(originalAliceKeyPair,
            "my pass phrase".toCharArray(), "Alice In Wonderland",
            secretKeyOutputStream, publicKeyOutputStream, true);
    
    // Imports the key pair from the exported data.
    KeyPair importedAliceKeyPair = CryptoUtil.importKeyPair(
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
    User alice = userFactory.createUser("Alice");
    PublicKey originalAlicePublicKey = alice.getKeyPair().getPublic();
    
    // Exports its public key.
    ByteArrayOutputStream publicKeyOutputStream = new ByteArrayOutputStream();
    CryptoUtil.exportPublicKey(originalAlicePublicKey, publicKeyOutputStream, true);
    
    // Imports the public key from the exported data.
    PublicKey importedAlicePublicKey = CryptoUtil.importPublicKey(
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
