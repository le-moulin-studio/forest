package com.lemoulinstudio.forest.platform.mina;

import com.lemoulinstudio.forest.platform.user.User;
import java.io.IOException;
import java.net.InetSocketAddress;
import org.apache.mina.core.service.IoHandler;
import org.apache.mina.transport.socket.nio.NioSocketAcceptor;

public class Server {
  
  private NioSocketAcceptor acceptor;
  
  public void start(User user) throws IOException {
    start(user, ForestIoHandler.getInstance());
  }
  
  public void start(User user, IoHandler ioHandler) throws IOException {
    acceptor = new NioSocketAcceptor();
    acceptor.getFilterChain().addLast("handshake", new ServerHandshakeFilter(user));
    acceptor.setHandler(ForestIoHandler.getInstance());
    acceptor.bind(new InetSocketAddress(user.getPort()));
  }
  
  public void close() {
    acceptor.unbind();
  }
  
}
