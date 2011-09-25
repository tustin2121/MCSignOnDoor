package org.digiplex.common;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
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
		BufferedReader r = new BufferedReader(new FileReader(file));
		String line;
		message = new StringBuilder();
		while ((line = r.readLine()) != null){
			message.append(line).append("\n");
		}
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
	
	public String execute(){
		StringBuilder finalmsg = new StringBuilder();
		StringTokenizer st = new StringTokenizer(message.toString(), "%");
		for (boolean literal = true; st.hasMoreTokens(); literal = !literal){
			if (literal){
				finalmsg.append(st.nextToken());
			} else {
				String token = st.nextToken();
				if (token.isEmpty()) finalmsg.append('%'); //"%%" => "%"
				else finalmsg.append(templateVariables.get(token));
			}
		}
		return finalmsg.toString();
	}
}
