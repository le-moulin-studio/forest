package com.lemoulinstudio.forest.platform.service;

import com.lemoulinstudio.small.apt.model.HostType;
import com.lemoulinstudio.small.apt.model.Log;
import com.lemoulinstudio.small.apt.model.Service;

@Log
@Service(HostType.Peer)
public interface NodeService {
  // Ask if the target on the other node is handled.
  public void pingToTarget(byte[] pingTarget);
  
  // Answer that the target is handled.
  public void pongFromTarget(byte[] pingTarget);
  
  // To transmit a message to an application target on the other node.
  public void appDataTransmission(byte[] targetId, byte[] data);
  
  // To transmit a message to an application target on the other node.
  public void appDataTransmission(int targetIndex, byte[] data);
}
