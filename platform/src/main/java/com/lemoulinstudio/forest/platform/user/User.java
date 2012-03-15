package com.lemoulinstudio.forest.platform.user;

import java.security.KeyPair;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

public class User {
  
  private String name;
  private KeyPair keyPair;
  private int port;
  private List<Contact> contactList;

  public User(String name, KeyPair keyPair) {
    this(name, keyPair, 8000 + new Random().nextInt(1000));
  }

  public User(String name, KeyPair keyPair, int port) {
    this.name = name;
    this.keyPair = keyPair;
    this.port = port;
    this.contactList = new ArrayList<Contact>();
  }

  public String getName() {
    return name;
  }

  public void setName(String name) {
    this.name = name;
  }

  public KeyPair getKeyPair() {
    return keyPair;
  }

  public int getPort() {
    return port;
  }

  public void setPort(int port) {
    this.port = port;
  }

  public List<Contact> getContactList() {
    return contactList;
  }

}
