package com.lemoulinstudio.forest.platform.mina;

import com.lemoulinstudio.forest.platform.user.Contact;
import com.lemoulinstudio.forest.platform.user.User;
import java.net.InetSocketAddress;
import org.apache.mina.core.future.ConnectFuture;
import org.apache.mina.core.service.IoHandler;
import org.apache.mina.core.session.IoSession;
import org.apache.mina.transport.socket.nio.NioSocketConnector;

public class Client {
  
  public IoSession connect(User user, Contact contact) {
    return connect(user, contact, ForestIoHandler.getInstance());
  }
  
  public IoSession connect(User user, Contact contact, IoHandler ioHandler) {
    NioSocketConnector connector = new NioSocketConnector();
    connector.getFilterChain().addLast("handshake", new ClientHandshakeFilter(user, contact));
    connector.setHandler(ForestIoHandler.getInstance());
    
    ConnectFuture connectFuture = connector.connect(new InetSocketAddress(contact.getInternetAddress(), contact.getPort()));
    connectFuture.awaitUninterruptibly();
    return connectFuture.getSession();
  }

}
