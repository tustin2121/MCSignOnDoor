package org.digiplex.common;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.Hashtable;
import java.util.StringTokenizer;


/**
 * Basically an incredibly lightweight version of the Velocity engine by the
 * Apache project.
 * @author Tim
 */
public class TemplateFormatter {
	private StringBuilder message;
	private Hashtable<String, String> templateVariables;
	
	public TemplateFormatter(String str){
		message = new StringBuilder(message);
		templateVariables = new Hashtable<String, String>();
	}
	public TemplateFormatter(File file) throws FileNotFoundException, IOException{
		BufferedReader r = new BufferedReader(new InputStreamReader(new FileInputStream(file), "UTF-8"));
		String line;
		message = new StringBuilder();
		while ((line = r.readLine()) != null){
			message.append(line).append("\n");
		}
		r.close();
		templateVariables = new Hashtable<String, String>();
	}
	public TemplateFormatter(URI file) throws FileNotFoundException, IOException {
		this(new File(file));
	}
	public TemplateFormatter(URL resource) throws FileNotFoundException, IOException, URISyntaxException {
		this(new File(resource.toURI()));
	}
	
	
	public void defineVariable(String var, String value){
		templateVariables.put(var, value);
	}
	
	public String execute() throws MalformedFormatException{
		StringBuilder finalmsg = new StringBuilder();
		StringTokenizer st = new StringTokenizer(message.toString(), "%", true);
		for (boolean literal = true; st.hasMoreTokens(); literal = !literal){
			String token = st.nextToken();
			if (token.length() > 1){
				finalmsg.append(token);
			} else {
				switch(token.charAt(0)){
					case '%': {
						String tk = st.nextToken();
						if (tk.equals("%")) {
							finalmsg.append('%'); break; //"%%" => "%"
						}
						finalmsg.append(templateVariables.get(token));
						if (!st.nextToken().equals("%")) 
							throw new MalformedFormatException("Escape % signs are mismatched.");
					} break;
//					case '&': {
//						String tk = st.nextToken();
//						Character.
//					} break;
					default:
						finalmsg.append(token);
				}
				
				
				
			}
		}
		return finalmsg.toString();
	}
	
	public static class MalformedFormatException extends Exception {
		private static final long serialVersionUID = 2357634760741327752L;
		public MalformedFormatException() {super();}
		public MalformedFormatException(String message, Throwable cause) {super(message, cause);}
		public MalformedFormatException(String message) {super(message);}
		public MalformedFormatException(Throwable cause) {super(cause);}
	}
}
