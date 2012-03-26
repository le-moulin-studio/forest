package com.lemoulinstudio.forest.platform.mina;

import com.lemoulinstudio.forest.platform.user.Contact;
import com.lemoulinstudio.forest.platform.user.User;
import com.lemoulinstudio.forest.platform.user.UserFactory;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.Security;
import org.apache.mina.core.session.IoSession;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.BeforeClass;
import org.junit.Test;

public class MinaHandshakeTest {
  
  public static final int userKeySizeInBits = 4096;
  
  public static User alice;
  public static User bob;
  
  @BeforeClass
  public static void setupBouncyCastle() throws Exception {
    // Registers Bouncy Castle as a provider for JCE.
    Security.addProvider(new BouncyCastleProvider());
    
    UserFactory userFactory = new UserFactory(userKeySizeInBits);
    alice = userFactory.createUser("Alice");
    bob = userFactory.createUser("Bob");
    
    alice.getContactList().add(createContact(bob));
    bob.getContactList().add(createContact(alice));
  }
  
  private static Contact createContact(User user) throws UnknownHostException {
    return new Contact(
            user.getName(),
            user.getKeyPair().getPublic(),
            InetAddress.getLocalHost(),
            user.getPort());
  }
  
  @Test
  public void testMinaAndSmall() throws Exception {
    Server server = new Server();
    server.start(alice);
    
    Client client = new Client();
    IoSession clientSession = client.connect(bob, bob.getContactList().get(0));
    
    while (!clientSession.isClosing())
      Thread.sleep(20);
    
    server.close();
  }
    
}
