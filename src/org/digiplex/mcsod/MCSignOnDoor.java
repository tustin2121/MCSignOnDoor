package org.digiplex.mcsod;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.UnsupportedEncodingException;
import java.net.BindException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URISyntaxException;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.nio.charset.CharsetDecoder;
import java.security.InvalidParameterException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Properties;
import java.util.logging.ConsoleHandler;
import java.util.logging.FileHandler;
import java.util.logging.Formatter;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.digiplex.common.ByteBuilder;
import org.digiplex.common.TemplateFormatter;


public class MCSignOnDoor {
	private static final Logger LOG = Logger.getLogger("McSod");
	private static final String VERSION = "1.6";
	private static final String BLACKLIST_IP_FILE = "banned-ips.txt";
	private static final String BLACKLIST_NAME_FILE = "banned-players.txt";
	private static final String WHITELIST_NAME_FILE = "white-list.txt";
	private static final String DEFAULT_LOGFILE = "mcsod.log";
	
	private static ServerSocket serve;
	private static int port = 25565;
	private static InetAddress ip = null;
	
	private static String awayMessage = "The server is not currently running.";
	
	private static String motdMessage = null; //"MCSignOnDoor: Server not Running.";
	private static String numplayers = "0", maxplayers = "0";
	private static boolean respondToPing = true, ratioSet = false;
	
	private static String basepath = "";//new File("").getPath()+File.separator;
	
	private static HashSet<String> blockedIps = null;
	private static String blockedMessage = null;
	
	private static HashSet<String> bannedUsers = null;
	private static String bannedMessage = null;
	
	private static HashSet<String> whiteUsers = null;
	private static String whitelistMessage = null;

	public static void main(String[] args) {
		parseCommandLine(args);
		determineDefaults();
		
		{//fix formatting on logger
			Logger rootlog = Logger.getLogger("");
			for (Handler h : rootlog.getHandlers()){ //remove all handlers
				h.setFormatter(new McSodFormatter());
			}
		}
		
		Runtime.getRuntime().addShutdownHook(new Thread(){
			@Override public void run() {
				LOG.info("Stopping message server.");
				try {
					if (serve != null) serve.close();
				} catch (IOException e) {}
			}
		});
		
		//Starting server
		LOG.info("MCSignOnDoor Client Notifier v"+VERSION+" by Tustin2121");
		if (ip != null)
			LOG.info("Starting server on "+ip+":"+port+" with message \""+awayMessage+"\"");
		else 
			LOG.info("Starting server on port "+port+" with message \""+awayMessage+"\"");
		if (respondToPing)
			LOG.info("Server set to respond to pings with motd \""+motdMessage+"\" and player ratio "+numplayers+"/"+maxplayers);
		else
			LOG.info("Server set to ignore pings.");
		
		if (awayMessage.length() > 80){
			LOG.warning("Message length exceeds 80 characters. Messages don't wrap on the client, even with newline characters, and may be cut off when shown.");
		}
		if (ratioSet){ //this is so we're not throwing this warning when the user doesn't explicitly set a ratio
			if ((!numplayers.matches("[0-9]+") || !maxplayers.matches("[0-9]+") || maxplayers.equals("0"))){
				LOG.warning("Player ratio may not be shown by client. Player ratio must be a valid, non-negative fraction to be displayed to the player.");
			}
		}
		
		try{
			if (ip == null){
				serve = new ServerSocket(port);
			} else {
				serve = new ServerSocket(port, 50, ip);
			}
			while(!serve.isClosed()){
				try {
					Socket s = serve.accept();
					LOG.info("Received connection from "+s.getInetAddress().getHostAddress());
					new ResponderThread(s).start();
				} catch (IOException e){
					LOG.log(Level.SEVERE, "IOException while accepting client!", e);
				}
			}
		} catch (SecurityException e){
			LOG.severe("Security exception while binding socket! Cannot start server.");
			System.exit(-1);
		} catch (BindException e){
			LOG.severe("Cannot bind to port "+port+".");
			if (ip != null) LOG.severe("Make sure the IP address entered is a valid IP address for this computer!");
			LOG.severe("Make sure the Minecraft Server is not still running and no other instances of MCSignOnDoor are running!");
			System.exit(-1);
		} catch (Exception e) {
			LOG.log(Level.SEVERE, "Unhandled exception in main loop!", e);
		} finally {
			try {serve.close();} catch (IOException e) {}
		}
	}
	
	///////////////////////////////////////////////////////////////////////////////////
	private static boolean checkMessageForSignOnDoor(String msg){
		if (msg.length() > 250){
			System.out.println("Message is too long. It cannot exceed 250 characters.");
			return false;
		}
		if (msg.endsWith("&")){
			System.out.println("Message ends with &, which is an incomplete color code and will crash the client.");
			return false;
		}
		return true;
	}
	
	public static boolean setAwayMessage(String away){
		if (!checkMessageForSignOnDoor(away)) return false;
		{
			Pattern p = Pattern.compile("\\\\\\!"); // "\\\!" - finding "\!"
			Matcher m = p.matcher(away);
			away = m
				.replaceAll("!")
				.replaceAll("(&([a-f0-9]))", "\u00A7$2"); //thanks to FrozenBrain for this code
		}
		awayMessage = away;
		return true;
	}
	public static boolean setBannedMessage(String away){
		if (!checkMessageForSignOnDoor(away)) return false;
		{
			Pattern p = Pattern.compile("\\\\\\!"); // "\\\!" - finding "\!"
			Matcher m = p.matcher(away);
			away = m
				.replaceAll("!")
				.replaceAll("(&([a-f0-9]))", "\u00A7$2"); //thanks to FrozenBrain for this code
		}
		bannedMessage = away;
		return true;
	}
	public static boolean setIpMessage(String away){
		if (!checkMessageForSignOnDoor(away)) return false;
		{
			Pattern p = Pattern.compile("\\\\\\!"); // "\\\!" - finding "\!"
			Matcher m = p.matcher(away);
			away = m
				.replaceAll("!")
				.replaceAll("(&([a-f0-9]))", "\u00A7$2"); //thanks to FrozenBrain for this code
		}
		blockedMessage = away;
		return true;
	}
	public static boolean setWhiteMessage(String away){
		if (!checkMessageForSignOnDoor(away)) return false;
		{
			Pattern p = Pattern.compile("\\\\\\!"); // "\\\!" - finding "\!"
			Matcher m = p.matcher(away);
			away = m
				.replaceAll("!")
				.replaceAll("(&([a-f0-9]))", "\u00A7$2"); //thanks to FrozenBrain for this code
		}
		whitelistMessage = away;
		return true;
	}
	public static boolean setMotdMessage(String motd){
		if (motd.contains("&")){
			System.out.println("Message of the Day cannot contain color symbols.");
			return false;
		}
		{
			Pattern p = Pattern.compile("\\\\\\!"); // "\\\!" - finding "\!"
			Matcher m = p.matcher(motd);
			motd = m
				.replaceAll("!");
		}
		motdMessage = motd;
		return true;
	}
	public static boolean setPlayerRatio(String ratio){
		ratioSet = true;
		Pattern p = Pattern.compile("^([^/]+)/(.+)$");
		Matcher m = p.matcher(ratio);
		if (m.find()){
			numplayers = m.group(1);
			maxplayers = m.group(2);
		} else {
			System.out.println("Invalid player ratio format. Please supply a string in the form \"X/Y\".");
			return false;
		}
		return true;
	}
	
	public static List<String> loadListing(String filename) throws FileNotFoundException, IOException{
		File f = new File(filename);
		if (!f.exists()) throw new FileNotFoundException(f.getAbsolutePath());
		BufferedReader br = new BufferedReader(new InputStreamReader(new FileInputStream(f)));
		ArrayList<String> listing = new ArrayList<String>();
		String line;
		while((line = br.readLine()) != null){
			listing.add(line);
		}
		br.close();
		return listing;
	}
	public static boolean loadIpList(String filename){
		if (blockedIps == null){
			blockedIps = new HashSet<String>();
		}
		try {
			blockedIps.addAll(loadListing(basepath + filename));
		} catch (FileNotFoundException ex){
			System.out.println("Could not find file: "+ex.getMessage());
		} catch (IOException ex){
			System.out.println("Fatal error while reading blacklist file: ");
			ex.printStackTrace();
		}
		return true;
	}
	public static boolean loadBlackList(String filename){
		if (bannedUsers == null){
			bannedUsers = new HashSet<String>();
		}
		try {
			bannedUsers.addAll(loadListing(basepath + filename));
		} catch (FileNotFoundException ex){
			System.out.println("Could not find file: "+ex.getMessage());
		} catch (IOException ex){
			System.out.println("Fatal error while reading blacklist file: ");
			ex.printStackTrace();
		}
		return true;
	}
	public static boolean loadWhiteList(String filename){
		if (whiteUsers == null){
			whiteUsers = new HashSet<String>();
		}
		try {
			whiteUsers.addAll(loadListing(basepath + filename));
		} catch (FileNotFoundException ex){
			System.out.println("Could not find file: "+ex.getMessage());
		} catch (IOException ex){
			System.out.println("Fatal error while reading blacklist file: ");
			ex.printStackTrace();
		}
		return true;
	}
	
	protected static void parseCommandLine(String[] args){
		LinkedList<String> argbuffer = new LinkedList<String>();
		Collections.addAll(argbuffer, args);
		try {
			while(!argbuffer.isEmpty()){
				String arg = argbuffer.pop();
				arg = arg.replace('/', '-');
				if (arg.equalsIgnoreCase("--help") || arg.equalsIgnoreCase("-?") || arg.equalsIgnoreCase("--version")){
					try {
						TemplateFormatter tf = new TemplateFormatter(
								MCSignOnDoor.class.getResource("helpfile"));
						tf.defineVariable("VERSION", VERSION);
						tf.defineVariable("PORT", Integer.toString(port));
						tf.defineVariable("AWAYMSG", awayMessage);
						String s = tf.execute();
						System.out.println(s);
					} catch (IOException ex){
						System.out.println("Error while printing helpfile: "+ ex.getMessage());
					} catch (URISyntaxException e) {
						System.out.println("Error while finding helpfile: "+ e.getMessage());
					} finally {
						System.exit(0);
					}
				} else if (arg.equalsIgnoreCase("-c") || arg.equalsIgnoreCase("--cfg") || arg.equalsIgnoreCase("--config")){
					parseConfigFile(new File(argbuffer.pop()));
					break; //parse only the config
				} else if (arg.equalsIgnoreCase("-p") || arg.equalsIgnoreCase("--port")){
					port = Integer.parseInt(argbuffer.pop());
				} else if (arg.equalsIgnoreCase("-ip") ||arg.equalsIgnoreCase("-i") || arg.equalsIgnoreCase("--address")){
					ip = InetAddress.getByName(argbuffer.pop());
				} else if (arg.equalsIgnoreCase("--ignoreping")){
					respondToPing = false;
				} else if (arg.equalsIgnoreCase("-m") || arg.equalsIgnoreCase("--message")){
					if (!setAwayMessage(argbuffer.pop())) { System.exit(-1); }
				} else if (arg.equalsIgnoreCase("--motd")){
					if (!setMotdMessage(argbuffer.pop())) { System.exit(-1); }
				} else if (arg.equalsIgnoreCase("--players") || arg.equalsIgnoreCase("--ratio")){
					if (!setPlayerRatio(argbuffer.pop())) { System.exit(-1); }
				} else if (arg.equalsIgnoreCase("-w") || arg.equalsIgnoreCase("--whitemessage") || arg.equalsIgnoreCase("--whitelist-message")){
					if (!setWhiteMessage(argbuffer.pop())) { System.exit(-1); }
				} else if (arg.equalsIgnoreCase("-b") || arg.equalsIgnoreCase("--blackmessage") || arg.equalsIgnoreCase("--blacklist-message")
						|| arg.equalsIgnoreCase("--bannedmessage") || arg.equalsIgnoreCase("--banned-message")){
					if (!setBannedMessage(argbuffer.pop())) { System.exit(-1); }
				} else if (arg.equalsIgnoreCase("--ipmessage")){
					if (!setIpMessage(argbuffer.pop())) { System.exit(-1); }
				} else if (arg.equalsIgnoreCase("--basepath")){
					basepath = new File(argbuffer.pop()).getPath()+File.separator;
				} else if (arg.equalsIgnoreCase("-l") || arg.equalsIgnoreCase("--log") || arg.equalsIgnoreCase("--logfile")){
					String logfilename;
					if (!argbuffer.peek().replace('/', '-').startsWith("-")){
						logfilename = argbuffer.pop();
					} else {
						logfilename = DEFAULT_LOGFILE;
					}
					Logger rootlog = Logger.getLogger("");
					rootlog.addHandler(new FileHandler(logfilename, true));
				} else if (arg.equalsIgnoreCase("-s") || arg.equalsIgnoreCase("--silent")){
					Logger rootlog = Logger.getLogger("");
					Handler hs[] = rootlog.getHandlers();
					for (Handler h : hs){
						if (h instanceof ConsoleHandler) rootlog.removeHandler(h);
					}
				} else {
					System.out.println("Unknown command line switch \""+arg+"\". Continuing...");
				}
			} //end while
		} catch (SecurityException e) {
			e.printStackTrace();
			System.out.println("You don't have proper permission to either open a file or access the network.");
		} catch (UnsupportedEncodingException e){
			e.printStackTrace();
			System.out.println("Encoding not supported.");
		} catch (UnknownHostException e){
			e.printStackTrace();
			System.out.println("Unknown host: the argument entered for ip address is not valid or could not be resolved to an ip address.");
		} catch (IOException e) {
			System.out.println("IOException during log file setup: "+e.getMessage());
		} finally {}
	}
	
	protected static void parseConfigFile(File config) {
		try {
			Reader br = new InputStreamReader(new FileInputStream(config));
			Properties p = new Properties();
			p.load(br);
			for (Object keyo : p.keySet()){
				String key = (String)keyo;
				if (key.equalsIgnoreCase("port")){
					port = Integer.parseInt(p.getProperty(key));
				} else if (key.equalsIgnoreCase("ip")){
					ip = InetAddress.getByName(p.getProperty(key));
				} else if (key.equalsIgnoreCase("ignoreping")){
					respondToPing = Boolean.parseBoolean(p.getProperty(key));
				} else if (key.equalsIgnoreCase("message")){
					if (!setAwayMessage(p.getProperty(key))) { System.exit(-1); }
				} else if (key.equalsIgnoreCase("motd")){
					if (!setMotdMessage(p.getProperty(key))) { System.exit(-1); }
				} else if (key.equalsIgnoreCase("playerratio")){
					if (!setPlayerRatio(p.getProperty(key))) { System.exit(-1); }
				} else if (key.equalsIgnoreCase("whitelistmessage")){
					if (!setWhiteMessage(p.getProperty(key))) { System.exit(-1); }
				} else if (key.equalsIgnoreCase("blacklistmessage") || key.equalsIgnoreCase("bannedlistmessage")){
					if (!setBannedMessage(p.getProperty(key))) { System.exit(-1); }
				} else if (key.equalsIgnoreCase("whitelistfile")){
					loadWhiteList(p.getProperty(key));
				} else if (key.equalsIgnoreCase("blacklistfile") || key.equalsIgnoreCase("bannedlistfile")){
					loadBlackList(p.getProperty(key));
				} else if (key.equalsIgnoreCase("basepath")){
					basepath = new File(p.getProperty(key)).getPath()+File.separator;
				} else if (key.equalsIgnoreCase("logfile")){
					String logfilename = p.getProperty(key);
					Logger rootlog = Logger.getLogger("");
					rootlog.addHandler(new FileHandler(logfilename, true));
				} else if (key.equalsIgnoreCase("silent")){
					if (Boolean.parseBoolean(p.getProperty(key))) {
						Logger rootlog = Logger.getLogger("");
						Handler hs[] = rootlog.getHandlers();
						for (Handler h : hs){
							if (h instanceof ConsoleHandler) rootlog.removeHandler(h);
						}
					}
				}
			}
		} catch (IOException e){
			System.out.println("IOException while attempting to load config file: "+e.getMessage());
		}
	}
	
	protected static void determineDefaults(){
		if (motdMessage != null){
			if (motdMessage.length()+numplayers.length()+maxplayers.length()+2 > 64){
				System.out.println("MotD is too long. The player ratio and the MotD combined " +
						"cannot exceed 64 characters. Note that the player ratio is sent as the top number and bottom " +
						"number as strings, with two extra characters separating them, totalling at least 4 characters.");
				System.exit(-1);
			}
		} else {
			motdMessage = awayMessage.replaceAll("(\u00A7([a-f0-9]))", "");
			int allowedlen = 64 - (2+numplayers.length()+maxplayers.length());
			if (motdMessage.length() > allowedlen){
				motdMessage = motdMessage.substring(0, 64-allowedlen);
				if (motdMessage.length() + 4 > awayMessage.length()) {//if the message was truncated substantially, add ellipses
					motdMessage = motdMessage.substring(0, motdMessage.length()-3).concat("...");
				}
			}
		}
		
		if (bannedMessage != null && bannedUsers == null){ //if a message was set but a file was not specified
			loadBlackList(BLACKLIST_NAME_FILE);
			if (blockedMessage == null){
				blockedMessage = bannedMessage; 
			}
			if (blockedIps == null) {
				loadIpList(BLACKLIST_IP_FILE);
			}
		}
		
		if (whitelistMessage != null && whiteUsers == null){ //if a message was set but a file was not specified 
			loadWhiteList(WHITELIST_NAME_FILE);
		}
	}
	
	///////////////////////////////////////////////////////////////////////////////////
	
	private static class ResponderThread extends Thread {
		private Socket sock;
		private BufferedInputStream in;
		private BufferedOutputStream out;
		
		ResponderThread(Socket s) {
			sock = s;
			try {
				in = new BufferedInputStream(s.getInputStream());
				out = new BufferedOutputStream(s.getOutputStream());
			} catch (IOException e) {
				LOG.log(Level.SEVERE, "IOException while setting up a responder thread!", e);
			}
		}
		
		@Override public void run() {
			try {
				byte[] inbyte = new byte[256];

				in.read(inbyte, 0, 1); //read connect byte
				if (inbyte[0] == (byte)0xFE) { //Minecraft 1.8 Server Ping
					if (!respondToPing) {
						LOG.info("Client pinging server. Ignoring.");
						return;
					}
					LOG.info("Client pinging server. Responding.");
					sendInfo(motdMessage, numplayers, maxplayers);
				} else {
					in.read(inbyte, 1, 2); //read message length
					int len = parseChar(inbyte, 1);
					in.read(inbyte, 3, len*2); //read message
					
					String reportedName;
					{
						ByteBuffer bb = ByteBuffer.wrap(Arrays.copyOfRange(inbyte, 3, (len+1)*2+1));
						CharsetDecoder d = Charset.forName("UTF-16BE").newDecoder();
						CharBuffer cb = d.decode(bb);
						reportedName = cb.toString();
						LOG.info("Reported client name: "+ reportedName +". Turning away.");
					}
					if (blockedMessage != null){
						if (!blockedIps.isEmpty() &&
								blockedIps.contains(sock.getInetAddress().getHostAddress())){
							LOG.info("Client found on the banned IPs list.");
							sendDisconnect(bannedMessage);
							return;
						}
					}
					if (bannedMessage != null){// bannedUsers != null){
						if (bannedUsers.contains(reportedName)) {
							LOG.info("Client found on the blacklist.");
							sendDisconnect(bannedMessage);
							return;
						}
					}
					if (whitelistMessage != null){// whiteUsers != null){
						if (whiteUsers.contains(reportedName)) {
							LOG.info("Client found on the whitelist.");
							sendDisconnect(whitelistMessage);
							return;
						}
					}
					
					sendDisconnect(awayMessage);
				}
			} catch (IOException e) {
				LOG.log(Level.SEVERE, "IOException while processing client!", e);
			} finally {
				try {sock.close();} catch (IOException e){}
			}
		}
		
		public short parseChar(byte[] arr, int off){
			final int LEN = 2; //long are 8 bytes long
			if (arr.length < LEN) throw new InvalidParameterException();
			
			byte[] b = Arrays.copyOfRange(arr, off, off+LEN);
			short value = 0;
			
			for (int i = 0; i < LEN; i++) {
				int offset = (b.length - 1 - i) * 8;
				long v = 0xFF & b[i]; //see note above
				value |= v << offset;
			}
			return value;
		}
		
		private void sendDisconnect(String message) throws IOException{
			ByteBuilder bb = new ByteBuilder();
			bb.append((byte)0xFF);
			bb.appendSpecial(message.length(), 2, false);
			bb.append(message);
			
//			System.out.println(bb.toString());
			out.write(bb.toByteArray());
			out.flush();
		}
		private void sendInfo(String message, String numPlayers, String maxPlayers) throws IOException {
			ByteBuilder bb = new ByteBuilder();
			bb.append((byte)0xFF);
			bb.appendSpecial(message.length()+numPlayers.length()+maxPlayers.length()+2, 2, false);
			bb.append(message);
			
			//if (sendPlayerRatio)
			{
				bb.append((byte)0).append((byte)0xA7);
				bb.append(numPlayers);
				bb.append((byte)0).append((byte)0xA7);
				bb.append(maxPlayers);
			}
//			System.out.println(bb.toString());
			out.write(bb.toByteArray());
			out.flush();
		}
		/*
		@SuppressWarnings("unused")
		private void sendConnect() throws IOException{
			out.write(new byte[]{(byte) 0x02});
			out.flush();
		}
		
		@SuppressWarnings("unused") 
		private void sendAck() throws IOException{
			out.write(new byte[]{(byte) 0x01});
			out.flush();
		}
		
		private void sendMessage(String message) throws IOException{
			ByteBuilder bb = new ByteBuilder();
			bb.append((byte)0x0);
			bb.appendSpecial(message.length(), 1, false);
			bb.append(message);
			
//			System.out.println(bb.toString());
			out.write(bb.toByteArray());
			out.flush();
		}*/
	}

}

class McSodFormatter extends Formatter {
	SimpleDateFormat dformat;
	
	public McSodFormatter(){
		dformat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss ");
	}

	@Override
	public String format(LogRecord record) {
		StringBuffer buf = new StringBuffer();
		buf
			.append(dformat.format(new Date(record.getMillis())))
			.append(record.getLoggerName())
			.append(" [").append(record.getLevel().getName()).append("]: ")
			.append(this.formatMessage(record)).append('\n');
		if (record.getThrown() != null){
			buf.append('\t').append(record.getThrown().toString()).append('\n');
		}
		return buf.toString();
	}

}
