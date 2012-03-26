package com.lemoulinstudio.forest.platform.user;

import com.lemoulinstudio.forest.platform.service.NodeService;
import java.net.InetAddress;
import java.security.PublicKey;
import org.jboss.netty.channel.Channel;

public class Contact {
  
  // The name and the publicKey can change, but we can keep track of the user with a local id.
  //private Long id;
  
  private String name;
  private PublicKey publicKey;
  private InetAddress internetAddress;
  private int port;
  
  private Channel channel;
  
  // This reference could be accessed via the ioSession, so it is redundant.
  // It is here as a convenient (and fast) way to access it.
  private NodeService nodeServiceProxy;

  public Contact(String name, PublicKey publicKey, InetAddress internetAddress, int port) {
    this.name = name;
    this.publicKey = publicKey;
    this.internetAddress = internetAddress;
    this.port = port;
  }

  public String getName() {
    return name;
  }

  public void setName(String name) {
    this.name = name;
  }
  
  public PublicKey getPublicKey() {
    return publicKey;
  }

  public void setPublicKey(PublicKey publicKey) {
    this.publicKey = publicKey;
  }

  public InetAddress getInternetAddress() {
    return internetAddress;
  }

  public void setInternetAddress(InetAddress internetAddress) {
    this.internetAddress = internetAddress;
  }

  public int getPort() {
    return port;
  }

  public void setPort(int port) {
    this.port = port;
  }

  public Channel getChannel() {
    return channel;
  }

  public void setChannel(Channel channel) {
    this.channel = channel;
  }

  public NodeService getNodeServiceProxy() {
    return nodeServiceProxy;
  }

  public void setNodeServiceProxy(NodeService nodeServiceProxy) {
    this.nodeServiceProxy = nodeServiceProxy;
  }
  
}
