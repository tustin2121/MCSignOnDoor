package org.digiplex.mcsod;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

final class ProtocolHandler {
	private static ProtocolHandler[] handlerStack;
	
	public static void defineProtocols() throws IOException, NumberFormatException, IllegalArgumentException {
		InputStream is = ProtocolHandler.class.getClassLoader().getResourceAsStream("META-INF/protocols.properties");
		Properties props = new Properties();
		props.load(is);
		
		int num = Integer.parseInt(props.getProperty("handlers.count"));
		if (num <= 0) throw new IllegalArgumentException("Invalid handler count!");
		handlerStack = new ProtocolHandler[num];
		
		for (int i = 0; i < num; i++) {
			ProtocolHandler ph = new ProtocolHandler();
			String key = "handlers."+i+".";
			
			ph.protoMin = Integer.parseInt(props.getProperty(key+"protocols.min"));
			ph.protoMax = Integer.parseInt(props.getProperty(key+"protocols.max"));
			ph.handshakeResponse = Integer.parseInt(props.getProperty(key+"protocols.handshake"));
			ph.disconnectResponse = Integer.parseInt(props.getProperty(key+"protocols.disconnect"));
			ph.motdResponse = Integer.parseInt(props.getProperty(key+"protocols.motd"));
			ph.encryptionResponse = Integer.parseInt(props.getProperty(key+"protocols.encryption"));
			
			handlerStack[i] = ph;
		}
	}
	
	public static ProtocolHandler getHandlerForProtocol(int protocolNum) {
		if (protocolNum < 0) return null;
		for (int i = handlerStack.length-1; i >= 0; i--) {
			ProtocolHandler ph = handlerStack[i];
			
			if (protocolNum < ph.protoMin) continue;
			if (protocolNum < ph.protoMax) return ph;
		}
		return null;
	}
	
	/////////////////////////////////////////////////
	
	private int protoMin, protoMax;
	public int handshakeResponse;
	public int disconnectResponse;
	public int motdResponse;
	public int encryptionResponse;
	
}
