package com.lemoulinstudio.forest.platform.mina;

import org.apache.mina.core.service.IoHandlerAdapter;
import org.apache.mina.core.session.IoSession;

public class HelloWorldMessageHandler extends IoHandlerAdapter {
  
  private final boolean isServerSide;

  public HelloWorldMessageHandler(boolean isServerSide) {
    this.isServerSide = isServerSide;
  }
  
  @Override
  public void sessionCreated(IoSession session) throws Exception {
    System.out.println(String.format("%s session created.", isServerSide ? "Server" : "Client"));
  }

  @Override
  public void sessionClosed(IoSession session) throws Exception {
    System.out.println(String.format("%s session closed.", isServerSide ? "Server" : "Client"));
  }

  @Override
  public void sessionOpened(IoSession session) throws Exception {
    if (!isServerSide)
      session.write("Hello Server!".getBytes());
  }

  @Override
  public void messageReceived(IoSession session, Object message) throws Exception {
    System.out.println(String.format("%s received: \"%s\"",
            isServerSide ? "Server" : "Client",
            new String((byte[]) message)));
    
    if (isServerSide)
      session.write("Hello Client!".getBytes());
    
    session.close(false);
  }

}
