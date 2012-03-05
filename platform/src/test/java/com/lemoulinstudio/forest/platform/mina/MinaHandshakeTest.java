package com.lemoulinstudio.forest.platform.mina;

import com.lemoulinstudio.forest.platform.User;
import com.lemoulinstudio.forest.platform.UserFactory;
import java.security.Security;
import java.util.Collections;
import java.util.Random;
import org.apache.mina.core.session.IoSession;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.BeforeClass;
import org.junit.Test;

public class MinaHandshakeTest {
  
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
  public void testMinaHandshake() throws Exception {
    Server server = new Server();
    Client client = new Client();
    int port = 8000 + new Random().nextInt(1000);
    
    server.start(
            alice.getKeyPair(),
            Collections.singleton(bob.getKeyPair().getPublic()),
            port,
            new HelloWorldMessageHandler(true));
    
    IoSession clientSession = client.connect(
            bob.getKeyPair(),
            alice.getKeyPair().getPublic(),
            "localhost",
            port,
            new HelloWorldMessageHandler(false));
    
    while (!clientSession.isClosing()) {
      Thread.sleep(20);
    }
    
    server.close();
  }
    
}
