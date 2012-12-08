package org.digiplex.mcsod;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.UnsupportedEncodingException;
import java.net.BindException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
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
import org.digiplex.common.TemplateFormatter.MalformedFormatException;


public class MCSignOnDoor {
	private static final Logger LOG = Logger.getLogger("McSod");
	private static final String VERSION = "1.8";
	private static final int CURRENT_PROTOCOL_VERSION; //set in constructor below
	
	static { //static constructor
		String protoversion = MCSignOnDoor.class.getPackage().getSpecificationVersion();
		if (protoversion == null) protoversion = /****/ "49" /****/; //up to date protocol version - UPDATE MANIFEST TOO!
		CURRENT_PROTOCOL_VERSION = Integer.parseInt(protoversion);
	}
	
	private static final String BLACKLIST_IP_FILE = "banned-ips.txt";
	private static final String BLACKLIST_NAME_FILE = "banned-players.txt";
	private static final String WHITELIST_NAME_FILE = "white-list.txt";
	private static final String DEFAULT_LOGFILE = "mcsod.log";
	
	private static ServerSocket serve;
	private static int port = 25565;
	private static InetAddress ip = null;
	
	private static int actAsVersion = -1;
	private static String reportedVersionNumber = "Offline";
	
	private static boolean sentryMode = false;
	
	private static String awayMessage = "The server is not currently running.";
	
	private static String motdMessage = null; //"MCSignOnDoor: Server not Running.";
	private static String numplayers = "0", maxplayers = "20";
	private static boolean respondToPing = true, ratioSet = false;
	
	private static String basepath = "";//new File("").getPath()+File.separator;
	private static String outputToConfig = null;
	
	private static boolean blockedIpLoaded = false;
	private static HashSet<String> blockedIps = null;
	private static String blockedMessage = null;
	private static boolean ignorePingFromBlocked = false;
	
	private static boolean bannedUsersLoaded = false;
	private static HashSet<String> bannedUsers = null;
	private static String bannedMessage = null;
	
	private static boolean whiteUsersLoaded = false;
	private static HashSet<String> whiteUsers = null;
	private static String whitelistMessage = null;

	public static void main(String[] args) {
		parseCommandLine(args);
		if (outputToConfig != null){
			makeConfigFile(new File(outputToConfig));
		}
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
		{
			LOG.info("MCSignOnDoor Client Notifier v"+VERSION+" by Tustin2121");
			if (ip != null)
				LOG.info("Starting server on "+ip+":"+port+" with message \""+awayMessage+"\"");
			else 
				LOG.info("Starting server on port "+port+" with message \""+awayMessage+"\"");
			if (respondToPing)
				LOG.info("Server set to respond to pings with motd \""+motdMessage+"\" and player ratio "+numplayers+"/"+maxplayers);
			else
				LOG.info("Server set to ignore pings.");
			
			if (sentryMode)
				LOG.info("Server set to sentry mode, will exit when someone connects.");
			
			LOG.info("Server protocol set to "+((actAsVersion < 0)?"latest ("+CURRENT_PROTOCOL_VERSION+")":"act as "+actAsVersion)+"."+
					((actAsVersion==-2)?" (Sending bad protocol number with MOTD to show version client-side)":""));
			
			if (awayMessage.length() > 80){
				LOG.warning("Message length exceeds 80 characters. You may add newlines by using the sequence \"\\n\" in a message.");
			}
			if (ratioSet){ //this is so we're not throwing this warning when the user doesn't explicitly set a ratio
				if ((!numplayers.matches("[0-9]+") || !maxplayers.matches("[0-9]+") || maxplayers.equals("0"))){
					LOG.warning("Player ratio may not be shown by client. Player ratio must be a valid, non-negative fraction to be displayed to the player.");
				}
			}
			
			if (whitelistMessage != null){
				if (!whiteUsersLoaded) {
					LOG.warning("There was an error loading the whitelist users.");
				} else {
					LOG.info("Whitelist message set: "+whitelistMessage);
					if (whiteUsers.isEmpty()) LOG.warning("There are no entries in the whitelist.");
				}
			}
			if (bannedMessage != null){
				if (!bannedUsersLoaded) {
					LOG.warning("There was an error loading the banned users.");
				} else {
					LOG.info("Banned list message set: "+bannedMessage);
					if (bannedUsers.isEmpty()) LOG.warning("There are no entries in the banned users list.");
				}
			}
			if (blockedMessage != null){
				if (!blockedIpLoaded) {
					LOG.warning("There was an error loading the banned IPs.");
				} else if (blockedMessage != bannedMessage) {
					//yes, string == string, because if the banned message is not explicitly set, it should be the same object
					LOG.info("Banned IP message set: "+blockedMessage);
					if (blockedIps.isEmpty()) LOG.warning("There are no entries in the banned IPs list.");
				}
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
				} catch (SocketException ex) {
					if (!serve.isClosed()) //if the socket is just closing, ignore this
						LOG.log(Level.SEVERE, "SocketException while accepting client!", ex);
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
	
	private static int getKnownProtocolVersion(int v) {
		if (v >= 49) return v; //allow higher numbers, since it seems to be rapidly rising
		if (v >= 47) return 47; //addition of encryption
		if (v >= 39) return 39; //change of handshake and login request, and also unicode.
		return 0; //before things reported protocol versions
	}
	
	///////////////////////////////////////////////////////////////////////////////////
	private static boolean checkMessageForSignOnDoor(String msg){
		if (msg.length() > 250){
			System.out.println("Message is too long. It cannot exceed 250 characters.");
			return false;
		}
		if (msg.endsWith("&")){
			System.out.println("Message ends with &, which is an incomplete color code.");
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
				.replaceAll("(&([a-f0-9]))", "\u00A7$2") //thanks to FrozenBrain for this code
				.replaceAll("\\\\n", "\n"); //translate literal \n to actual new lines
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
				.replaceAll("(&([a-f0-9]))", "\u00A7$2") //thanks to FrozenBrain for this code
				.replaceAll("\\\\n", "\n"); //translate literal \n to actual new lines
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
				.replaceAll("(&([a-f0-9]))", "\u00A7$2") //thanks to FrozenBrain for this code
				.replaceAll("\\\\n", "\n"); //translate literal \n to actual new lines
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
				.replaceAll("(&([a-f0-9]))", "\u00A7$2") //thanks to FrozenBrain for this code
				.replaceAll("\\\\n", "\n"); //translate literal \n to actual new lines
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
				.replaceAll("!")
				.replaceAll("\\n", ""); //remove newlines from the motd message
		}
		motdMessage = motd;
		return true;
	}
	public static boolean setReportedVersion(String ver) {
		reportedVersionNumber = ver; //everything works
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
			blockedIpLoaded = true;
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
			bannedUsersLoaded = true;
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
			whiteUsersLoaded = true;
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
				//arg = arg.replace('/', '-');
				if (arg.equalsIgnoreCase("--help") || arg.equalsIgnoreCase("-?") || arg.equalsIgnoreCase("--version")){
					try {
						TemplateFormatter tf = new TemplateFormatter(
								MCSignOnDoor.class.getResourceAsStream("helpfile"));
						tf.defineVariable("VERSION", VERSION);
						tf.defineVariable("PORT", Integer.toString(port));
						tf.defineVariable("AWAYMSG", awayMessage);
						tf.defineVariable("VERDEF", reportedVersionNumber);
						String s = tf.execute();
						System.out.println(s);
					} catch (FileNotFoundException e) {
						System.out.println("Error while finding helpfile: "+ e.getMessage());
					} catch (IOException ex){
						System.out.println("Error while printing helpfile: "+ ex.getMessage());
					} catch (MalformedFormatException e) {
						System.out.println("===PROGRAMMER ERROR=== "+e.getMessage());
					} catch (Exception e) {
						//because the finally exits, we need to catch remaining errors here.
						System.err.println("UNHANDLED ERROR while processing helpfile.");
						e.printStackTrace();
					} finally {
						System.exit(0);
					}
				} else if (arg.equalsIgnoreCase("--outputconfig")){
					outputToConfig = argbuffer.pop();
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
				} else if (arg.equalsIgnoreCase("-v") || arg.equalsIgnoreCase("--reported-version")){
					if (!setReportedVersion(argbuffer.pop())) { System.exit(-1); }
				} else if (arg.equalsIgnoreCase("--players") || arg.equalsIgnoreCase("--ratio")){
					if (!setPlayerRatio(argbuffer.pop())) { System.exit(-1); }
				} else if (arg.equalsIgnoreCase("-w") || arg.equalsIgnoreCase("--whitemessage") || arg.equalsIgnoreCase("--whitelist-message")){
					if (!setWhiteMessage(argbuffer.pop())) { System.exit(-1); }
				} else if (arg.equalsIgnoreCase("-b") || arg.equalsIgnoreCase("--blackmessage") || arg.equalsIgnoreCase("--blacklist-message")
						|| arg.equalsIgnoreCase("--bannedmessage") || arg.equalsIgnoreCase("--banned-message")){
					if (!setBannedMessage(argbuffer.pop())) { System.exit(-1); }
				} else if (arg.equalsIgnoreCase("--ipmessage")){
					if (!setIpMessage(argbuffer.pop())) { System.exit(-1); }
				} else if (arg.equalsIgnoreCase("--ignorebannedping")){
					ignorePingFromBlocked = true;
				} else if (arg.equalsIgnoreCase("--basepath")){
					basepath = new File(argbuffer.pop()).getPath()+File.separator;
				} else if (arg.equalsIgnoreCase("--sentrymode")){
					sentryMode = true;
				} else if (arg.equalsIgnoreCase("-l") || arg.equalsIgnoreCase("--log") || arg.equalsIgnoreCase("--logfile")){
					String logfilename;
					if (!argbuffer.peek().startsWith("-")){
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
				} else if (arg.equalsIgnoreCase("--show-version") || arg.equalsIgnoreCase("-#")) {
					actAsVersion = -2; //Hack to get the mc client to report "out of date", which shows the version number
				} else if (arg.equalsIgnoreCase("--act-as-protocol")){
					actAsVersion = getKnownProtocolVersion(Integer.parseInt(argbuffer.pop()));
				} else {
					System.out.println("Unknown command line switch \""+arg+"\". Continuing...");
				}
			} //end while
		} catch (NumberFormatException e) {
			System.out.println("Invalid format for an argument: expected integer but found something else!");
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
			
			String val;
			if ((val = p.getProperty("server.port")) != null)
				port = Integer.parseInt(val);
			if ((val = p.getProperty("server.ip")) != null)
				ip = InetAddress.getByName(val);
			if ((val = p.getProperty("server.ignore.ping")) != null)
				respondToPing = !Boolean.parseBoolean(val);
			if ((val = p.getProperty("server.ignore.bannedping")) != null)
				ignorePingFromBlocked = Boolean.parseBoolean(val);
			
			if ((val = p.getProperty("mode.sentry")) != null)
				sentryMode = Boolean.parseBoolean(val);
			
			if ((val = p.getProperty("message.away")) != null)
				if (!setAwayMessage(val)) { System.exit(-1); }
			if ((val = p.getProperty("message.whitelist")) != null)
				if (!setWhiteMessage(val)) { System.exit(-1); }
			if ((val = p.getProperty("message.blacklist")) != null)
				if (!setBannedMessage(val)) { System.exit(-1); }
			if ((val = p.getProperty("message.bannedip")) != null)
				if (!setIpMessage(val)) { System.exit(-1); }
			
			if ((val = p.getProperty("message.motd")) != null)
				if (!setMotdMessage(val)) { System.exit(-1); }
			if ((val = p.getProperty("message.motd.playerratio")) != null)
				if (!setPlayerRatio(val)) { System.exit(-1); }
			if ((val = p.getProperty("message.motd.reportedversion")) != null)
				if (!setReportedVersion(val)) { System.exit(-1); }
			
			if ((val = p.getProperty("file.whitelist")) != null)
				loadWhiteList(val);
			if ((val = p.getProperty("file.blacklist")) != null)
				loadBlackList(val);
			if ((val = p.getProperty("file.bannedip")) != null)
				loadIpList(val);
			if ((val = p.getProperty("file.basepath")) != null)
				basepath = new File(val).getPath()+File.separator;
			
			if ((val = p.getProperty("advanced.forceversion")) != null) //not in config.template
				actAsVersion = -2;
			if ((val = p.getProperty("advanced.actas")) != null) //not in config.template
				actAsVersion = getKnownProtocolVersion(Integer.getInteger(val));
			
			
			if ((val = p.getProperty("file.log")) != null) {
				String logfilename = val;
				Logger rootlog = Logger.getLogger("");
				rootlog.addHandler(new FileHandler(logfilename, true));
			}
			if ((val = p.getProperty("sever.silent")) != null) {
				if (Boolean.parseBoolean(val)) {
					Logger rootlog = Logger.getLogger("");
					Handler hs[] = rootlog.getHandlers();
					for (Handler h : hs){
						if (h instanceof ConsoleHandler) rootlog.removeHandler(h);
					}
				}
			}
			
			/*
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
				} else if (key.equalsIgnoreCase("bannedipmessage") || key.equalsIgnoreCase("bannedlistmessage")){
					if (!setIpMessage(p.getProperty(key))) { System.exit(-1); }
				} else if (key.equalsIgnoreCase("whitelistfile")){
					loadWhiteList(p.getProperty(key));
				} else if (key.equalsIgnoreCase("blacklistfile") || key.equalsIgnoreCase("bannedlistfile")){
					loadBlackList(p.getProperty(key));
				} else if (key.equalsIgnoreCase("bannedipfile")){
					loadBlackList(p.getProperty(key));
				} else if (key.equalsIgnoreCase("ignorebannedping")){
					ignorePingFromBlocked = Boolean.parseBoolean(p.getProperty(key));
				} else if (key.equalsIgnoreCase("basepath")){
					basepath = new File(p.getProperty(key)).getPath()+File.separator;
				} else if (key.equalsIgnoreCase("reportedversion")){
					reportedVersionNumber = p.getProperty(key);
				} else if (key.equalsIgnoreCase("sentrymode")){
					sentryMode = Boolean.parseBoolean(p.getProperty(key));
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
			}*/
		} catch (NumberFormatException e) {
			System.out.println("NumberFormatException while parsing config file: expected integer but found something else!");
		} catch (IOException e){
			System.out.println("IOException while attempting to load config file: "+e.getMessage());
		}
	}
	protected static void makeConfigFile(File config) {
		try {
			System.out.println("Configuration file write requested. Started...");
			TemplateFormatter tf = new TemplateFormatter(MCSignOnDoor.class.getResource("config.template"));
			
			tf.defineVariable("H_PORT", (port == 25565)?"#":"");
			tf.defineVariable("V_PORT", Integer.toString(port));
			
			tf.defineVariable("H_IP", (ip == null)?"#":"");
			tf.defineVariable("V_IP", (ip == null)?"":ip.getHostAddress());
			
			tf.defineVariable("H_PING", (respondToPing)?"#":"");
			tf.defineVariable("V_PING", Boolean.toString(!respondToPing));
			
			tf.defineVariable("H_MSG", "");
			tf.defineVariable("V_MSG", awayMessage);
			
			tf.defineVariable("H_SNTRY", (!sentryMode)?"#":"");
			tf.defineVariable("V_SNTRY", Boolean.toString(sentryMode));
			
			tf.defineVariable("H_MOTD", (motdMessage == null)?"#":"");
			tf.defineVariable("V_MOTD", (motdMessage == null)?"":motdMessage);
			
			tf.defineVariable("H_RATIO", (!ratioSet)?"#":"");
			tf.defineVariable("V_RATIO", numplayers+"/"+maxplayers);
			
			tf.defineVariable("H_WLMSG", (whitelistMessage == null)?"#":"");
			tf.defineVariable("V_WLMSG", (whitelistMessage == null)?"":whitelistMessage);
			
			tf.defineVariable("H_WLF", "#"); 
			//this is technically a bug, since it's not using the inputted file, but whatever
			tf.defineVariable("V_WLF", WHITELIST_NAME_FILE);
			
			tf.defineVariable("H_BLMSG", (bannedMessage == null)?"#":"");
			tf.defineVariable("V_BLMSG", (bannedMessage == null)?"":bannedMessage);
			
			tf.defineVariable("H_BLF", "#"); //this is technically a bug, see above
			tf.defineVariable("V_BLF", BLACKLIST_NAME_FILE);
			
			tf.defineVariable("H_IPMSG", (blockedMessage == null)?"#":"");
			tf.defineVariable("V_IPMSG", (blockedMessage == null)?"":blockedMessage);
			
			tf.defineVariable("H_IPF", "#"); //this is technically a bug, see above
			tf.defineVariable("V_IPF", BLACKLIST_IP_FILE);
			
			tf.defineVariable("H_IPPING", (!ignorePingFromBlocked)?"#":"");
			tf.defineVariable("V_IPPING", Boolean.toString(ignorePingFromBlocked));
			
			tf.defineVariable("H_BASE", (basepath.isEmpty())?"#":"");
			tf.defineVariable("V_BASE", basepath);
			
			tf.defineVariable("H_MOTDVER", "#");
			tf.defineVariable("V_MOTDVER", reportedVersionNumber);
			
			tf.defineVariable("H_LOG", "#");
			//this is technically a bug, since it's not using the inputted filename, but whatever
			tf.defineVariable("V_LOG", DEFAULT_LOGFILE);
			
			tf.defineVariable("H_SILENT", "#"); //also technically a bug, but again, whatever
			tf.defineVariable("V_SILENT", "true");
			
			BufferedWriter w = new BufferedWriter(new FileWriter(config));
			try {
				w.write(tf.execute());
				System.out.println("Completed.");
			} catch (MalformedFormatException e) {
				System.out.println("===PROGRAMMER ERROR=== "+e.getMessage());
			} finally {
				w.close();
			}
		} catch (FileNotFoundException e) {
			System.out.println("===PROGRAMMER ERROR=== "+e.getMessage());
		} catch (IOException e) {
			System.out.println("Error writing config file: "+e.getMessage());
		} catch (URISyntaxException e) {
			System.out.println("===PROGRAMMER ERROR=== "+e.getMessage());
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
			motdMessage = awayMessage.replaceAll("(\u00A7([a-f0-9]))", "").replaceAll("\\n", " ");
			int allowedlen = 64 - (2+numplayers.length()+maxplayers.length());
			if (motdMessage.length() > allowedlen){
				motdMessage = motdMessage.substring(0, allowedlen);
				if (motdMessage.length() + 4 < awayMessage.length()) {//if the message was truncated substantially, add ellipses
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
			boolean sentryActivated = false;
			StringBuilder SBL = new StringBuilder();
			
			try {
				byte[] inbyte = new byte[256];
				boolean isBlocked = (blockedMessage != null) && (!blockedIps.isEmpty() &&
						blockedIps.contains(sock.getInetAddress().getHostAddress()));
				
				in.read(inbyte, 0, 1); //read connect byte
				if (inbyte[0] == (byte)0xFE) { //Minecraft 1.8 Server Ping
					if (!respondToPing) {
						SBL.append("Client pinging server. Ignoring.");
						return;
					}
					if (ignorePingFromBlocked && isBlocked){
						SBL.append("Client found on the banned IPs list pinging server. Ignoring.");
						return;
					}
					
					int version = 0;
					if (actAsVersion <= -1 || actAsVersion > 46) { //grab the byte only if not dealing with motd ver 0
						in.read(inbyte, 1, 1); //read "motd version", byte length
						version = inbyte[1];
					}
					SBL.append("Client pinging server. Responding.");
					sendInfo(version);
					
					
				} else if (inbyte[0] == (byte)0x02) { //Handshake, pre-login
					in.read(inbyte, 1, 1); //read "protocol version", byte length
					int version = inbyte[1];
					String reportedName = null, reportedServer = null; int reportedPort = 0;
					
					if (actAsVersion > -1) { //if acting as a specific protocol version
						if (version != actAsVersion)
							LOG.warning("Client's protocol version does not match version McSod is acting as! Client="+version+", McSod="+actAsVersion);
						version = actAsVersion;
					}
					
					switch (version) {
					//CASE 0: this is for pre-version 1.3.1, when there was no version number
					case 0: { 
						in.read(inbyte, 2, 1); //read another byte, for message length
						int len = parseChar(inbyte, 1);
						in.read(inbyte, 3, len*2); //read message
						
						{
							ByteBuffer bb = ByteBuffer.wrap(Arrays.copyOfRange(inbyte, 3, (len+1)*2+1));
							CharsetDecoder d = Charset.forName("UTF-16BE").newDecoder();
							CharBuffer cb = d.decode(bb);
							reportedName = cb.toString();
							SBL.append("Reported client name: ").append(reportedName);// +". Turning away.");
						}
					} break;
					
					case 39: //CASE 39: this is for version 1.3.1, introduction of the protocol version
					case 47: //CASE 47: this is for version 1.4.2, identical for this part here
					case 49: //CASE 49: version 1.4.4, no change to protocol
					{
						in.read(inbyte, 2, 2); //read 16-byte number, message length
						int len = parseChar(inbyte, 2);
						in.read(inbyte, 4, len*2); //read username
						{
							ByteBuffer bb = ByteBuffer.wrap(Arrays.copyOfRange(inbyte, 4, 4+(len*2)));
							CharsetDecoder d = Charset.forName("UTF-16BE").newDecoder();
							CharBuffer cb = d.decode(bb);
							reportedName = cb.toString();
							SBL.append("Reported client name: \"").append(reportedName).append('"');
						}
						
						Arrays.fill(inbyte, (byte)0); //clear the buffer for the next read
						
						in.read(inbyte, 0, 2); //read 16-byte number, message length
						len = parseChar(inbyte, 0);
						in.read(inbyte, 3, len*2); //read server name
						{
							ByteBuffer bb = ByteBuffer.wrap(Arrays.copyOfRange(inbyte, 3, (len+1)*2+1));
							CharsetDecoder d = Charset.forName("UTF-16BE").newDecoder();
							CharBuffer cb = d.decode(bb);
							reportedServer = cb.toString();
							SBL.append(", Server name: \"").append(reportedServer).append('"');
						}
						
						in.read(inbyte, 0, 4);
						reportedPort = parseInt(inbyte, 0);
						SBL.append(", Port: ").append(reportedPort);
						
					} break;
					
					//DEFAULT CASE: This is for when the protocol is updated and we have no idea what to do with it.
					default: {
						SBL.append("Client with unknown version (").append(version).append(") of Handshake Protocol attempting login! Printing raw data:\n");
						in.read(inbyte, 2, 250);
						StringBuffer charData = new StringBuffer();
						for (int i = 0; i < inbyte.length; i++) {
							SBL.append(String.format("%2X ", inbyte[i]));
							if (Character.isLetterOrDigit(inbyte[i]))
								charData.append(inbyte[i]);
							else
								charData.append(' ');
						}
						SBL.append('\n').append("Readable items: ").append(charData).append("\nFeel free to give tustin2121 this information on the bukkit thread. :)");
						
						sendDisconnect(awayMessage);
						return;
					}
					}
					
					
					if (version >= 47) { //since protocol version 47, Encryption!
				//		spoofEncryptionHandshake(); //spoof the encryption start, and then disconnect as if something went wrong in verification
					}
					
					
					if (isBlocked){
						SBL.append(". Client found on the banned IPs list. The bastard.");
						sendDisconnect(blockedMessage);
						return;
					}
					if (bannedMessage != null){// bannedUsers != null){
						if (bannedUsers.contains(reportedName)) {
							SBL.append(". Client found on the blacklist. Shooing.");
							sendDisconnect(bannedMessage);
							return;
						}
					}
					if (whitelistMessage != null){// whiteUsers != null){
						if (whiteUsers.contains(reportedName)) {
							SBL.append(". Client found on the whitelist. Giving candy.");
							sendDisconnect(whitelistMessage);
							sentryActivated = true;
							return;
						}
					}
					
					SBL.append(". Turning away.");
					sendDisconnect(awayMessage);
					sentryActivated = true;
				} //*/
			} catch (IOException e) {
				LOG.log(Level.SEVERE, "IOException while processing client!", e);
			} finally {
				LOG.info(SBL.toString());
				try {sock.close();} catch (IOException e){}
			}
			
			if (sentryMode && sentryActivated) {
				LOG.info("As per Sentry Mode, now shutting down.");
				System.exit(12);
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
		
		public int parseInt(byte[] arr, int off){
			final int LEN = 4; //long are 8 bytes long
			if (arr.length < LEN) throw new InvalidParameterException();
			
			byte[] b = Arrays.copyOfRange(arr, off, off+LEN);
			int value = 0;
			
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
		private void sendInfo(int version) throws IOException {
			switch (version) {
			case 0: {
				ByteBuilder bb = new ByteBuilder();
				bb.append((byte)0xFF);
				bb.appendSpecial(motdMessage.length()+numplayers.length()+maxplayers.length()+2, 2, false);
				bb.append(motdMessage);
				
				//if (sendPlayerRatio)
				{
					bb.append((byte)0).append((byte)0xA7);
					bb.append(numplayers);
					bb.append((byte)0).append((byte)0xA7);
					bb.append(maxplayers);
				}
				out.write(bb.toByteArray());
				out.flush();
			} break;
			case 1: { //protocol version 47 update, motd version 1
				StringBuilder sb = new StringBuilder();
				sb.append('\u00A7').append('1').append('\0'); //motd version indicator and version number
				if (actAsVersion == -1)
					sb.append(CURRENT_PROTOCOL_VERSION).append('\0'); //protocol version number
				else
					sb.append(actAsVersion).append('\0'); //protocol version number
				sb.append(reportedVersionNumber).append('\0');
				sb.append(motdMessage).append('\0');
				sb.append(numplayers).append('\0');
				sb.append(maxplayers).append('\0');
				
				ByteBuilder bb = new ByteBuilder();
				bb.append((byte)0xFF);
				bb.appendSpecial(sb.length(), 2, false);
				bb.append(sb.toString());
				
				out.write(bb.toByteArray());
				out.flush();
			} break;
			}
			
		}
		
		private static final byte key[] = new byte[1024]; //the key is all 0's
		private void spoofEncryptionHandshake() throws IOException {
			//This method makes it look like we're starting an encryption handshake, but before anything
			//serious happens, we stop this and kick them unencrypted.
			
			ByteBuilder bb = new ByteBuilder();
			bb.append((byte)0xFD); //encryption request
			bb.append((byte)0x00).append((byte)0x06); //TODO test what a server id is //Server Id
			bb.append("000000");
			bb.appendSpecial(1024, 2, false); //the encryption key
			bb.append(key);
			bb.appendSpecial(4, 2, false); //the verification number
			bb.append(new byte[]{10, 4, 21, 21});
			
			out.write(bb.toByteArray());
			out.flush();
			
			byte b[] = new byte[1];
			while (true) {
				in.read(b); //wait for response before continuing
				if (b[0] == 0xFC) break;
			}
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
