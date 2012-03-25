package com.lemoulinstudio.forest.platform.netty;

import com.lemoulinstudio.forest.platform.user.Contact;
import com.lemoulinstudio.forest.platform.user.User;
import com.lemoulinstudio.forest.platform.user.UserFactory;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.jboss.netty.channel.ChannelPipeline;
import org.jboss.netty.channel.ChannelPipelineFactory;
import org.jboss.netty.channel.Channels;
import org.junit.BeforeClass;
import org.junit.Test;

public class NettyHandshakeTest {
  
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
  public void testNettyAndSmall() throws Exception {
    Server server = new Server();
    server.start(alice, new ChannelPipelineFactory() {
      @Override
      public ChannelPipeline getPipeline() throws Exception {
        return Channels.pipeline(new HelloWorldMessageHandler(true));
      }
    });
    
    Client client = new Client();
    client.connect(bob, bob.getContactList().get(0), new ChannelPipelineFactory() {
      @Override
      public ChannelPipeline getPipeline() throws Exception {
        return Channels.pipeline(new HelloWorldMessageHandler(false));
      }
    });
    
    // Wait until the client channel is closed.
    client.close();
    
    // Wait until the server channel is closed.
    server.close();
  }
    
}
