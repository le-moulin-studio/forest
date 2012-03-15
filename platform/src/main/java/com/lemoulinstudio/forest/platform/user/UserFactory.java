package com.lemoulinstudio.forest.platform.user;

import com.lemoulinstudio.forest.platform.crypto.CryptoUtil;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import org.bouncycastle.openpgp.PGPException;

public class UserFactory {
  
  public final int keySize;

  public UserFactory() {
    this(4096);
  }

  public UserFactory(int keySize) {
    this.keySize = keySize;
  }

  public User createUser(String name)
          throws NoSuchProviderException,
                 NoSuchAlgorithmException,
                 InvalidKeyException,
                 SignatureException,
                 PGPException,
                 IOException {
    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
    keyPairGenerator.initialize(keySize);
    KeyPair keyPair = keyPairGenerator.generateKeyPair();
    
    // Exports the key pair.
    ByteArrayOutputStream secretKeyOutputStream = new ByteArrayOutputStream();
    ByteArrayOutputStream publicKeyOutputStream = new ByteArrayOutputStream();
    CryptoUtil.exportKeyPair(keyPair,
            "".toCharArray(), "",
            secretKeyOutputStream, publicKeyOutputStream, false);
    
    // Import the key pair, so that P < Q in the private key.
    KeyPair importedKeyPair = CryptoUtil.importKeyPair(
            new ByteArrayInputStream(secretKeyOutputStream.toByteArray()),
            "".toCharArray(), false);
    
    return new User(name, importedKeyPair);
  }
  
  public User createUser(String name, InputStream inputStream, char[] passPhrase, boolean armor)
          throws IOException, NoSuchProviderException, PGPException {
    KeyPair keyPair = CryptoUtil.importKeyPair(inputStream, passPhrase, armor);
    return new User(name, keyPair);
  }

}
