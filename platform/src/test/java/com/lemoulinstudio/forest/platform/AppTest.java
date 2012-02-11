package com.lemoulinstudio.forest.platform;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Security;
import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;

public class AppTest extends TestCase {

  public static Test suite() {
    return new TestSuite(AppTest.class);
  }

  public AppTest(String testName) {
    super(testName);
  }

  public void testPublicKeyExportImport() throws NoSuchProviderException, NoSuchAlgorithmException, PGPException, IOException {
    Security.addProvider(new BouncyCastleProvider());

    // Creates a new user.
    User aliceUser = UserFactory.createUser("Alice");
    PublicKey originalAlicePublicKey = aliceUser.getPublicKey();
    
    // Exports its public key.
    ByteArrayOutputStream publicKeyOutputStream = new ByteArrayOutputStream();
    KeyExporter.exportPublicKey(originalAlicePublicKey, publicKeyOutputStream, true);
    
    // Imports the public key from the exported data.
    PublicKey importedAlicePublicKey = KeyImporter.importPublicKey(
            new ByteArrayInputStream(publicKeyOutputStream.toByteArray()),
            true);
    
    // The public keys should be equal.
    assertTrue(originalAlicePublicKey.equals(importedAlicePublicKey));
  }
}
