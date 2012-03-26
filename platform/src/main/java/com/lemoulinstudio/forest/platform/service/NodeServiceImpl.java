package com.lemoulinstudio.forest.platform.service;

import com.lemoulinstudio.forest.platform.user.Contact;
import org.jboss.netty.channel.Channel;

public class NodeServiceImpl implements NodeService {
  
  private final Contact contact;
  private final Channel channel;

  public NodeServiceImpl(Contact contact, Channel channel) {
    this.contact = contact;
    this.channel = channel;
  }

  @Override
  public void pingToTarget(byte[] target) {
    System.out.println(String.format("Received pingToTarget(\"%s\")", new String(target)));
    contact.getNodeServiceProxy().pongFromTarget(target);
  }

  @Override
  public void pongFromTarget(byte[] target) {
    System.out.println(String.format("Received pongFromTarget(\"%s\")", new String(target)));
    channel.close();
  }

  @Override
  public void appDataTransmission(byte[] targetId, byte[] data) {
  }

  @Override
  public void appDataTransmission(int targetIndex, byte[] data) {
  }

}
