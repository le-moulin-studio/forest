package com.lemoulinstudio.forest.platform;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyPair;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;

public class KeyImporter {

  static KeyPair importKeyPair(InputStream inputStream, char[] passPhrase, boolean armor)
          throws IOException, NoSuchProviderException, PGPException {
    if (armor) {
      inputStream = new ArmoredInputStream(inputStream);
    }
    
    PGPSecretKeyRing secretKeyRing = new PGPSecretKeyRing(inputStream);
    
    PGPSecretKey secretKey = secretKeyRing.getSecretKey();
    PGPPublicKey publicKey = secretKey.getPublicKey();
    PGPPrivateKey privateKey = secretKey.extractPrivateKey(passPhrase, "BC");
    
    return new KeyPair(publicKey.getKey("BC"), privateKey.getKey());
  }
  
  public static PublicKey importPublicKey(InputStream inputStream, boolean armor)
          throws IOException, NoSuchProviderException, PGPException {
    
    if (armor) {
      inputStream = new ArmoredInputStream(inputStream);
    }
    
    PGPPublicKeyRing publicKeyRing = new PGPPublicKeyRing(inputStream);
    
    return publicKeyRing.getPublicKey().getKey("BC");
  }

}
