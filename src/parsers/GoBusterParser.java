package parsers;

import burp.IBurpExtenderCallbacks;

import java.net.MalformedURLException;
import java.net.URL;

/***
 * This parser handles output from the GoBuster tool. It expects you to run it
 * with the -e flag so the whole url is there and not just the path.
 */
public class GoBusterParser extends BaseParser {

    public GoBusterParser(IBurpExtenderCallbacks callbacks){
        super(callbacks);
    }

    /**
     * Parsing GoBuster is relatively simple, each line has a url followed by a
     * (Status: XXX) HTTP code indicator
     * @param urlString line of output containing a url
     * @return URL object for burp to process
     * @throws MalformedURLException thrown in case you mess up parsing it
     */
    @Override
    URL parseDirectory(String urlString) throws MalformedURLException {
        return new URL(urlString.split(" \\(")[0]);
    }

}
