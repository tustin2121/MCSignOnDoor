import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.BindException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.nio.charset.CharsetDecoder;
import java.security.InvalidParameterException;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.LinkedList;
import java.util.logging.ConsoleHandler;
import java.util.logging.FileHandler;
import java.util.logging.Formatter;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


public class MCSignOnDoor {
	private static final Logger LOG = Logger.getLogger("McSod");
	private static final String VERSION = "1.4";
	
	private static ServerSocket serve;
	private static int port = 25565;
	private static InetAddress ip = null;
	private static String awayMessage = "The server is not currently running.";
	private static String motdMessage = "MCSignOnDoor: Server not Running.";
	private static String numplayers = "0", maxplayers = "0";
	private static boolean respondToPing = true, ratioSet = false;

	public static void main(String[] args) {
		{ //parse command line switches
			LinkedList<String> argbuffer = new LinkedList<String>();
			Collections.addAll(argbuffer, args);
			try {
				boolean custommotd = false;
				while(!argbuffer.isEmpty()){
					String arg = argbuffer.pop();
					arg = arg.replace('/', '-');
					if (arg.equalsIgnoreCase("--help") || arg.equalsIgnoreCase("-?") || arg.equalsIgnoreCase("--version")){
						System.out.println(
							"MINECRAFT Sign On Door\n" +
							"Version "+VERSION+"\n" +
							"by Tustin2121\n" +
							"----------------------\n" +
							"This program tells players attempting to connect to a minecraft server\n" +
							"on this machine a message (defaulting to a 'server is off' message).\n" +
							"This program cannot and is not meant to run while the minecraft server\n" +
							"itself is running; it is meant to give a message to players as to why\n" +
							"the server is not running.\n" +
							"\n" +
							"Usage: java -jar MCSignOnDoor.jar [switches]\n" +
							"Command line switches:\n" +
							"	-? --help	Displays this message and quits\n" +
							"	-p --port	Sets the port the messenger runs on (default: "+port+")\n" +
							"	-i --address	Sets the ip address the messenger runs on (default: null)\n" +
							"	-m --message	Sets the message to send to connecting players (250 char max)\n" +
							"		(default: \""+awayMessage+"\")\n" +
							"      --motd    Sets the server list message of the day. (Defaults to truncated\n" +
							"        message setting)\n" +
							"      --ignoreping   Sets McSod to ignore incoming pings. Server appears offline.\n" +
							"      --players    Sets the player ratio given in pings. (in form \"1/10\")*\n" +
							"	-l --logfile	Supplies a log file to write to (default: does not use log file)\n" +
							"	-s --silent		Does not print output to the screen" +
							"\n" +
							"Notes:\n" +
							"Some command lines treat the bang (!) as a special command character.\n" +
							"If you would like to use a bang in your server message, be sure to escape\n" +
							"it with a backslash (\\).\n" +
							"Messages can also contain color codes by using an ampersand (&) followed by\n" +
							"a hexadecimal value (0-9 a-f). See the MC wiki's Classic Server Protocol page.\n" +
							"When setting the player ratio to show, non-numbers and a ratio with 0 max players\n" +
							"will display as \"???\" on the client. Player ratio also cuts into the max length\n" +
							"of the message of the day.\n" +
							"\n" +
							"Usage examples:\n" +
							"java -jar MCSignOnDoor\n" +
							"java -jar MCSignOnDoor -m \"The server is down for maintenance.\"\n" +
							"java -jar MCSignOnDoor -ip 192.168.1.1 -m \"Still waiting for bukkit to upgrade...\"\n" +
							"java -jar MCSignOnDoor -p 54321 --message \"The &eMinecraftWB &fserver has\n" +
							"    moved to 192.168.1.1\\!\" --motd \"Moved to 192.168.1.1\"\n" +
							"java -jar MCSignOnDoor -l logfile.log -s -m \"Slim's server is currently\n" +
							"    being removed of excessive genitalia.\" --motd \"Removing d*cks\" --players \"6/9\"\n"
						);
						System.exit(0);
					} else if (arg.equalsIgnoreCase("-p") || arg.equalsIgnoreCase("--port")){
						port = Integer.parseInt(argbuffer.pop());
					} else if (arg.equalsIgnoreCase("-ip") ||arg.equalsIgnoreCase("-i") || arg.equalsIgnoreCase("--address")){
						ip = InetAddress.getByName(argbuffer.pop());
					} else if (arg.equalsIgnoreCase("--ignoreping")){
						respondToPing = false;
					} else if (arg.equalsIgnoreCase("-m") || arg.equalsIgnoreCase("--message")){
						awayMessage = argbuffer.pop();
						if (awayMessage.length() > 250){
							System.out.println("Message is too long. It cannot exceed 250 characters.");
							System.exit(-1);
						}
						if (awayMessage.endsWith("&")){
							System.out.println("Message ends with &, which is an incomplete color code and will crash the client.");
							System.exit(-1);
						}
						{
							Pattern p = Pattern.compile("\\\\\\!"); // "\\\!" - finding "\!"
							Matcher m = p.matcher(awayMessage);
							awayMessage = m
								.replaceAll("!")
								.replaceAll("(&([a-f0-9]))", "\u00A7$2"); //thanks to FrozenBrain for this code
						}
						//awayMessage.getBytes("UTF8");
					} else if (arg.equalsIgnoreCase("--motd")){
						custommotd = true;
						motdMessage = argbuffer.pop();
						if (motdMessage.contains("&")){
							System.out.println("Message of the Day cannot contain color symbols.");
							System.exit(-1);
						}
						{
							Pattern p = Pattern.compile("\\\\\\!"); // "\\\!" - finding "\!"
							Matcher m = p.matcher(motdMessage);
							motdMessage = m
								.replaceAll("!");
						}
						//awayMessage.getBytes("UTF8");
					} else if (arg.equalsIgnoreCase("--players") || arg.equalsIgnoreCase("--ratio")){
						ratioSet = true;
						String ratio = argbuffer.pop();
						Pattern p = Pattern.compile("^([^/]+)/(.+)$");
						Matcher m = p.matcher(ratio);
						if (m.find()){
							numplayers = m.group(1);
							maxplayers = m.group(2);
						} else {
							System.out.println("Invalid player ratio format. Please supply a string in the form \"X/Y\".");
							System.exit(-1);
						}
						
					} else if (arg.equalsIgnoreCase("-l") || arg.equalsIgnoreCase("--logfile")){
						String logfilename = argbuffer.pop();
						Logger rootlog = Logger.getLogger("");
						rootlog.addHandler(new FileHandler(logfilename, true));
					} else if (arg.equalsIgnoreCase("-s") || arg.equalsIgnoreCase("--silent")){
						Logger rootlog = Logger.getLogger("");
						Handler hs[] = rootlog.getHandlers();
						for (Handler h : hs){
							if (h instanceof ConsoleHandler) rootlog.removeHandler(h);
						}
					}
				} //end while
				
				if (custommotd){
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
					
					{
						ByteBuffer bb = ByteBuffer.wrap(Arrays.copyOfRange(inbyte, 3, (len+1)*2+1));
						CharsetDecoder d = Charset.forName("UTF-16BE").newDecoder();
						CharBuffer cb = d.decode(bb);
						LOG.info("Reported client name: "+ cb.toString() +". Turning away.");
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
