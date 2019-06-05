package parsers;

import burp.HttpRequestResponse;
import burp.IBurpExtenderCallbacks;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;

/***
 * This base class forms the foundation for parsing output from directory
 * brute-force tools such as GoBuster. The base class takes care of converting
 * the URL into a IHttpRequestResponse object and adding it to burp. You just
 * have to implement the parseDirectory function which directs the extension
 * on how to parse each line of output.
 */
abstract class BaseParser extends JPanel implements ActionListener {
    private IBurpExtenderCallbacks callbacks;
    private JButton openButton;
    private final JFileChooser fc = new JFileChooser();

    BaseParser(IBurpExtenderCallbacks callbacks){
        this.callbacks = callbacks;
        openButton = new JButton("Open a File...");
        openButton.addActionListener(this);
        add(openButton);
    }

    /**
     * Returns the burp callback class
     * @return reference to burp callback class
     */
    IBurpExtenderCallbacks getCallbacks(){
        return this.callbacks;
    }

    /***
     * This is the method you must implement to tell DirectoryImporter how to
     * handle each line of output from the brute-force tool
     * @param urlString line of output containing a url
     * @return URL object for burp to process
     * @throws MalformedURLException thrown in case you mess up parsing it
     */
    abstract URL parseDirectory(String urlString) throws MalformedURLException;

    private HttpRequestResponse generateRequestResponse(String urlString)
            throws MalformedURLException{
        URL url = parseDirectory(urlString);
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

    /**
     * This handles the button click, building the burp object and adding it to
     * the sitemap
     * @param e the ActionEvent object
     */
    @Override
    public void actionPerformed(ActionEvent e) {
        if (e.getSource() == openButton) {
            int returnVal = fc.showOpenDialog(BaseParser.this);
            if (returnVal == JFileChooser.APPROVE_OPTION) {
                File file = fc.getSelectedFile();
                try (BufferedReader br =
                             new BufferedReader(new FileReader(file))) {
                    String st;
                    while ((st = br.readLine()) != null) {

                        HttpRequestResponse requestResponse =
                                this.generateRequestResponse(st);
                        Runnable task2 =
                                () -> this.callbacks.addToSiteMap(
                                        this.callbacks.makeHttpRequest(
                                                requestResponse.getHttpService(),
                                                requestResponse.getRequest()));
                        new Thread(task2).start();
                    }
                } catch (IOException ex) {
                    try {
                        this.callbacks.getStderr().write(ex.getMessage().getBytes());
                    } catch (IOException exc) {
                        this.callbacks.unloadExtension();
                    }
                }
            }
        }
    }
}
