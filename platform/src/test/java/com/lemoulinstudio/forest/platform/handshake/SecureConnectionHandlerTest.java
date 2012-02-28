package com.lemoulinstudio.forest.platform.handshake;

import com.lemoulinstudio.forest.platform.User;
import com.lemoulinstudio.forest.platform.UserFactory;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import static org.junit.Assert.*;
import org.junit.BeforeClass;
import org.junit.Test;

public class SecureConnectionHandlerTest {
  
  public static final int userKeysize = 4096;
  
  public static User alice;
  public static User bob;
  
  @BeforeClass
  public static void setupBouncyCastle() throws Exception {
    // Registers Bouncy Castle as a provider for JCE.
    Security.addProvider(new BouncyCastleProvider());
    
    UserFactory userFactory = new UserFactory(userKeysize);
    alice = userFactory.createUser("Alice");
    bob = userFactory.createUser("Bob");
  }
  
  @Test
  public void testConstantSizeOfRequest() throws Exception {
    ClientSecureConnectionHandler clientHandler = new ClientSecureConnectionHandler(
            alice.getKeyPair(),
            bob.getKeyPair().getPublic());
    
    int expectedRequestSize = clientHandler.createConnectionRequest().length;
    for (int i = 0; i < 1024; i++) {
      byte[] connectionRequest = clientHandler.createConnectionRequest();
      assertEquals(connectionRequest.length, expectedRequestSize);
    }
    
    System.out.println("Expected request size = " + expectedRequestSize);
  }

  @Test
  public void testHandshake() throws Exception {
    ClientSecureConnectionHandler clientHandler = new ClientSecureConnectionHandler(
            alice.getKeyPair(),
            bob.getKeyPair().getPublic());
    
    ServerSecureConnectionHandler serverHandler = new ServerSecureConnectionHandler(
            bob.getKeyPair(),
            alice.getKeyPair().getPublic());
    
    // ...
  }

}
