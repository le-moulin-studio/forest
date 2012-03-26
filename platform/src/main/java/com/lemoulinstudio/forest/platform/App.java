package com.lemoulinstudio.forest.platform;

import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class App {

  public static void main(String[] args)
          throws Exception {
    Security.addProvider(new BouncyCastleProvider());
    
  }
  
}
