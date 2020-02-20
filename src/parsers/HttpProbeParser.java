package parsers;

import burp.IBurpExtenderCallbacks;

import javax.swing.*;
import java.net.MalformedURLException;
import java.net.URL;

public class HttpProbeParser extends BaseParser {
    public HttpProbeParser(IBurpExtenderCallbacks callbacks) {
        super(callbacks);
    }

    @Override
    URL parseDirectory(String urlString) throws MalformedURLException {
        URL returningURL = new URL(urlString);
        if(returningURL.getPort() == -1) {
            returningURL = returningURL.getProtocol().equals("https") ?
                    new URL(urlString+":443") : new URL(urlString+":80");
        }
        return returningURL;
    }

    @Override
    JPanel buildOptionsPanel() {
        return null;
    }
}
