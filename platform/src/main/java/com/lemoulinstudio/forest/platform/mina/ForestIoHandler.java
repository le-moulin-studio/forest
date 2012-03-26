package com.lemoulinstudio.forest.platform.mina;

import com.lemoulinstudio.forest.platform.crypto.CryptoUtil;
import com.lemoulinstudio.forest.platform.service.Configuration;
import com.lemoulinstudio.forest.platform.service.NodeService;
import com.lemoulinstudio.forest.platform.service.NodeServiceImpl;
import com.lemoulinstudio.forest.platform.user.Contact;
import com.lemoulinstudio.forest.platform.user.User;
import com.lemoulinstudio.small.AbstractConfiguration;
import com.lemoulinstudio.small.MessageSender;
import com.lemoulinstudio.small.SmallSession;
import com.lemoulinstudio.small.SmallSessionImpl;
import java.net.InetSocketAddress;
import org.apache.mina.core.service.IoHandlerAdapter;
import org.apache.mina.core.session.AttributeKey;
import org.apache.mina.core.session.IoSession;

public final class ForestIoHandler extends IoHandlerAdapter {
  
  private static final ForestIoHandler instance = new ForestIoHandler();
  
  public static ForestIoHandler getInstance() {
    return instance;
  }
  
  private static final AbstractConfiguration configuration = new Configuration();

  public static final AttributeKey INITIATED_BY_ME = new AttributeKey(ForestIoHandler.class, "initiatedByMe");
  public static final AttributeKey USER = new AttributeKey(ForestIoHandler.class, "user");
  public static final AttributeKey CONTACT = new AttributeKey(ForestIoHandler.class, "contact");
  
  private static final AttributeKey SMALL_SESSION = new AttributeKey(ForestIoHandler.class, "smallSession");

  public static SmallSession getSmallSession(IoSession session) {
    return (SmallSession) session.getAttribute(SMALL_SESSION);
  }

  private ForestIoHandler() {
  }

  @Override
  public void sessionCreated(final IoSession session) throws Exception {
    // This connection was initiated by me? (i.e. Did I connected this contact?)
    boolean initiatedByMe = (Boolean) session.getAttribute(INITIATED_BY_ME);
    session.removeAttribute(INITIATED_BY_ME);
    
    // Identify the current user.
    User user = (User) session.getAttribute(USER);
    //session.removeAttribute(USER);
    
    // Identify the caller.
    Contact contact = (Contact) session.getAttribute(CONTACT);
    //session.removeAttribute(CONTACT);
    
    // We handle the case where a new connection is made while an existing one is already there.
    if (contact.getIoSession() != null) {
      // We already have a connection, we need to cut one of them.
      // We choose to cut the connection initiated by the peer with the smallest public key.
      boolean myPublicKeyIsSmaller = CryptoUtil.isSmallerThan(user.getKeyPair().getPublic(), contact.getPublicKey());
      
      boolean contactIpStillTheSame = ((InetSocketAddress) session.getRemoteAddress())
              .getAddress().equals(contact.getInternetAddress());
      
      if (contactIpStillTheSame && (myPublicKeyIsSmaller == initiatedByMe)) {
        // We close the new connection.
        session.close(true);
        return;
      }
      else {
        // We close the existing connection.
        contact.getIoSession().close(true);
      }
    }
    
    // Create the Small session.
    SmallSession smallSession = new SmallSessionImpl(configuration);
    session.setAttribute(SMALL_SESSION, smallSession);
    
    smallSession.setCallerObject(contact);
    
    // Configure the message sender.
    smallSession.setMessageSender(new MessageSender() {
      @Override
      public void sendMessage(byte[] binaryMessage) {
        session.write(binaryMessage);
      }
    });
    
    // Define our local service.
    smallSession.bind(new NodeServiceImpl(contact, session), NodeService.class);

    // Create a proxy to the remove service.
    NodeService nodeServiceProxy = smallSession.createProxy(NodeService.class);
    
    // Attach the session to the contact object.
    synchronized(contact) {
      contact.setIoSession(session);
      contact.setNodeServiceProxy(nodeServiceProxy);
    }
  }

  @Override
  public void sessionOpened(IoSession session) throws Exception {
    Contact contact = (Contact) session.getAttribute(CONTACT);
    
    contact.getNodeServiceProxy().pingToTarget("helloWorldTarget".getBytes());
  }

  @Override
  public void sessionClosed(IoSession session) throws Exception {
    Contact contact = (Contact) getSmallSession(session).getCallerObject();
    
    synchronized(contact) {
      if (contact.getIoSession() == session) {
        contact.setIoSession(null);
        contact.setNodeServiceProxy(null);
      }
    }
    
    session.removeAttribute(USER);
    session.removeAttribute(CONTACT);
    session.removeAttribute(SMALL_SESSION);
  }

  @Override
  public void exceptionCaught(IoSession session, Throwable cause) throws Exception {
    cause.printStackTrace();
    session.close(false);
  }
  
  @Override
  public void messageReceived(IoSession session, Object message) throws Exception {
    getSmallSession(session).decodeAndExecute((byte[]) message);
  }
  
}
