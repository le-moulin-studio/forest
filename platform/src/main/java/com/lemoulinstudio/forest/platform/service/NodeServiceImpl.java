package com.lemoulinstudio.forest.platform.service;

import com.lemoulinstudio.forest.platform.user.Contact;
import org.apache.mina.core.session.IoSession;

public class NodeServiceImpl implements NodeService {
  
  private final Contact contact;
  private final IoSession ioSession;

  public NodeServiceImpl(Contact contact, IoSession ioSession) {
    this.contact = contact;
    this.ioSession = ioSession;
  }

  @Override
  public void pingToTarget(byte[] target) {
    System.out.println(String.format("Received pingToTarget(\"%s\")", new String(target)));
    contact.getNodeServiceProxy().pongFromTarget(target);
  }

  @Override
  public void pongFromTarget(byte[] target) {
    System.out.println(String.format("Received pongFromTarget(\"%s\")", new String(target)));
    ioSession.close(false);
  }

  @Override
  public void appDataTransmission(byte[] targetId, byte[] data) {
  }

  @Override
  public void appDataTransmission(int targetIndex, byte[] data) {
  }

}
