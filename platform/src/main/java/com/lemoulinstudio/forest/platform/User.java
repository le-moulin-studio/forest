package com.lemoulinstudio.forest.platform;

import java.security.PrivateKey;
import java.security.PublicKey;

public class User {
  
  private PublicKey publicKey;
  private PrivateKey privateKey;
  private String name;

  public User(PublicKey publicKey, PrivateKey privateKey, String name) {
    this.publicKey = publicKey;
    this.privateKey = privateKey;
    this.name = name;
  }

  public PublicKey getPublicKey() {
    return publicKey;
  }
  
  public PrivateKey getPrivateKey() {
    return privateKey;
  }

  public String getName() {
    return name;
  }

  public void setName(String name) {
    this.name = name;
  }

}
