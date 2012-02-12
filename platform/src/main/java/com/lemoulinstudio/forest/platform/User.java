package com.lemoulinstudio.forest.platform;

import java.security.KeyPair;

public class User {
  
  private KeyPair keyPair;
  private String name;

  public User(KeyPair keyPair, String name) {
    this.keyPair = keyPair;
    this.name = name;
  }

  public KeyPair getKeyPair() {
    return keyPair;
  }

  public String getName() {
    return name;
  }

  public void setName(String name) {
    this.name = name;
  }

}
