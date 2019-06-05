package parsers;

import burp.HttpRequestResponse;
import burp.IBurpExtenderCallbacks;

import java.net.MalformedURLException;
import java.net.URL;

public class GoBusterParser extends BaseParser {

    public GoBusterParser(IBurpExtenderCallbacks callbacks){
        super(callbacks);
    }

    @Override
    HttpRequestResponse parseDirectory(String urlString) throws MalformedURLException {
        URL url = new URL(urlString.split(" \\(")[0]);
        HttpRequestResponse reqResp = new HttpRequestResponse();
        byte[] httpRequest = this.getCallbacks().getHelpers()
                .buildHttpRequest(url);
        reqResp.setRequest(httpRequest);
        reqResp.setHttpService(this.getCallbacks().getHelpers()
                .buildHttpService(
                        url.getHost(),
                        url.getPort() == -1 ? 443 :
                                url.getPort(),
                        true));
        return reqResp;
    }
}
