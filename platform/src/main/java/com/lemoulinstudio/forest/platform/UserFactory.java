package com.lemoulinstudio.forest.platform;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

public class UserFactory {
  
  //public static final int keySize = 4096;
  public static final int keySize = 1024;
  
  public static User createUser(String name) throws NoSuchProviderException, NoSuchAlgorithmException {
    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
    keyPairGenerator.initialize(keySize);
    KeyPair keyPair = keyPairGenerator.generateKeyPair();
    User user = new User(keyPair.getPublic(), keyPair.getPrivate(), name);
    return user;
  }
  
}
