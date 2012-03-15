package com.lemoulinstudio.forest.platform.mina;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import org.apache.mina.core.filterchain.IoFilter;
import org.apache.mina.core.session.AttributeKey;
import org.apache.mina.core.session.IoSession;
import org.apache.mina.core.write.WriteRequest;
import org.apache.mina.filter.util.WriteRequestFilter;

public class PacketFilter extends WriteRequestFilter {
  
  private static final AttributeKey DECODING_CONTEXT =
          new AttributeKey(PacketFilter.class, "decodingContext");

  private static final PacketFilter instance = new PacketFilter();

  public static PacketFilter getInstance() {
    return instance;
  }
  
  private PacketFilter() {
  }

  @Override
  public void sessionCreated(NextFilter nextFilter, IoSession session) throws Exception {
    super.sessionCreated(nextFilter, session);
    session.setAttribute(DECODING_CONTEXT, new DecodingContext());
  }

  @Override
  public void sessionClosed(NextFilter nextFilter, IoSession session) throws Exception {
    super.sessionClosed(nextFilter, session);
    session.removeAttribute(DECODING_CONTEXT);
  }
  
  @Override
  public void messageReceived(IoFilter.NextFilter nextFilter, IoSession session, Object message) throws Exception {
    ((DecodingContext) session.getAttribute(DECODING_CONTEXT)).decode(nextFilter, session, message);
  }

  @Override
  protected Object doFilterWrite(IoFilter.NextFilter nextFilter, IoSession session, WriteRequest writeRequest) throws Exception {
    byte[] byteArray = (byte[]) writeRequest.getMessage();
    
    ByteArrayOutputStream packet = new ByteArrayOutputStream(4 + byteArray.length);
    DataOutputStream dos = new DataOutputStream(packet);
    
    dos.writeInt(byteArray.length);
    dos.write(byteArray);
    
    return packet.toByteArray();
  }

  private static class DecodingContext {

    private static enum DecodingState {
      MessageSize,
      MessageContent
    }
    
    private DecodingState decodingState = DecodingState.MessageSize;
    private int messageLength = 0;
    private int nbBytesToRead = 4;
    private byte[] outMessage;
    private int outMessageIndex = 0;

    public void decode(IoFilter.NextFilter nextFilter, IoSession session, Object message) throws Exception {
      ByteArrayInputStream in = new ByteArrayInputStream((byte[]) message);
      
      while (in.available() > 0) {
        if (decodingState == DecodingState.MessageSize) {
          do {
            messageLength <<= 8;
            messageLength |= in.read() & 0xff;
            nbBytesToRead--;
            if (nbBytesToRead == 0) {
              decodingState = DecodingState.MessageContent;
              nbBytesToRead = messageLength;
              outMessage = new byte[messageLength];
              break;
            }
          } while (in.available() > 0);
        }

        if (decodingState == DecodingState.MessageContent) {
          outMessageIndex += in.read(outMessage, outMessageIndex, outMessage.length - outMessageIndex);

          // If we receive the whole message content ..
          if (outMessageIndex == outMessage.length) {
            // We send the buffer.
            nextFilter.messageReceived(session, outMessage);

            // Re-init decoding state variable.
            decodingState = DecodingState.MessageSize;
            messageLength = 0;
            nbBytesToRead = 4;
            outMessage = null;
            outMessageIndex = 0;
          }
        }
      }
    }
    
  }
  
}
