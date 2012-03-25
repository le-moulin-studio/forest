package com.lemoulinstudio.forest.platform.netty;

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
import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.buffer.ChannelBuffers;
import org.jboss.netty.channel.Channel;
import org.jboss.netty.channel.ChannelHandlerContext;
import org.jboss.netty.channel.ChannelStateEvent;
import org.jboss.netty.channel.ExceptionEvent;
import org.jboss.netty.channel.MessageEvent;
import org.jboss.netty.channel.SimpleChannelUpstreamHandler;

public class ForestChannelHandler extends SimpleChannelUpstreamHandler {

  private static final AbstractConfiguration configuration = new Configuration();
  
  private final boolean initiatedByMe;
  private final User user;
  private final Contact contact;
  private SmallSession smallSession;

  public ForestChannelHandler(boolean initiatedByMe,
                              User user,
                              Contact contact) {
    this.initiatedByMe = initiatedByMe;
    this.user = user;
    this.contact = contact;
  }

  @Override
  public void channelOpen(ChannelHandlerContext ctx, ChannelStateEvent e) throws Exception {
    // We handle the case where a new connection is made while an existing one is already there.
    if (contact.getChannel() != null) {
      // We already have a connection, we need to cut one of them.
      // We choose to cut the connection initiated by the peer with the smallest public key.
      boolean myPublicKeyIsSmaller = CryptoUtil.isSmallerThan(user.getKeyPair().getPublic(), contact.getPublicKey());
      
      boolean contactIpStillTheSame = ((InetSocketAddress) ctx.getChannel().getRemoteAddress())
              .getAddress().equals(contact.getInternetAddress());
      
      if (contactIpStillTheSame && (myPublicKeyIsSmaller == initiatedByMe)) {
        // We close the new connection.
        ctx.getChannel().close();
        return;
      }
      else {
        // We close the existing connection.
        contact.getChannel().close();
      }
    }
    
    // Create the Small session.
    smallSession = new SmallSessionImpl(configuration);
    smallSession.setCallerObject(contact);
    
    // Configure the message sender.
    final Channel channel = ctx.getChannel();
    smallSession.setMessageSender(new MessageSender() {
      @Override
      public void sendMessage(byte[] binaryMessage) {
        channel.write(ChannelBuffers.wrappedBuffer(binaryMessage));
      }
    });
    
    // Define our local service.
    smallSession.bind(new NodeServiceImpl(contact, channel), NodeService.class);

    // Create a proxy to the remove service.
    NodeService nodeServiceProxy = smallSession.createProxy(NodeService.class);
    
    // Attach the session to the contact object.
    synchronized(contact) {
      contact.setChannel(channel);
      contact.setNodeServiceProxy(nodeServiceProxy);
    }
  }

  @Override
  public void channelConnected(ChannelHandlerContext ctx, ChannelStateEvent e) throws Exception {
    contact.getNodeServiceProxy().pingToTarget("helloWorldTarget".getBytes());
  }

  @Override
  public void channelClosed(ChannelHandlerContext ctx, ChannelStateEvent e) throws Exception {
    synchronized(contact) {
      // In case 2 channels were created at the same time, this makes sure that
      // we update the contact only for the officially chosen channel.
      if (contact.getChannel() == ctx.getChannel()) {
        contact.setIoSession(null);
        contact.setNodeServiceProxy(null);
      }
    }
  }

  @Override
  public void exceptionCaught(ChannelHandlerContext ctx, ExceptionEvent e) throws Exception {
    System.err.println(e.getCause().toString());
    ctx.getChannel().close();
  }

  @Override
  public void messageReceived(ChannelHandlerContext ctx, MessageEvent e) throws Exception {
    smallSession.decodeAndExecute(((ChannelBuffer) e.getMessage()).array());
  }
  
}
