package com.lemoulinstudio.forest.platform.service;

import com.lemoulinstudio.forest.platform.user.Contact;
import org.apache.mina.core.session.IoSession;
import org.jboss.netty.channel.Channel;

public class NodeServiceImpl implements NodeService {
  
  private final Contact contact;
  private final IoSession ioSession; // TODO: get rid of this field.
  private final Channel channel;

  public NodeServiceImpl(Contact contact, IoSession ioSession) {
    this.contact = contact;
    this.ioSession = ioSession;
    this.channel = null;
  }

  public NodeServiceImpl(Contact contact, Channel channel) {
    this.contact = contact;
    this.ioSession = null;
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
    if (ioSession != null) ioSession.close(true);
    if (channel != null) channel.close();
  }

  @Override
  public void appDataTransmission(byte[] targetId, byte[] data) {
  }

  @Override
  public void appDataTransmission(int targetIndex, byte[] data) {
  }

}
