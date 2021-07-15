package parsers;

import burp.HttpRequestResponse;
import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import burp.IResponseInfo;

import javax.swing.*;
import java.awt.*;
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
abstract public class BaseParser extends JPanel implements ActionListener {
    private final JCheckBox followRedirectsCheckBox;
    private final JCheckBox makeRequestsCheckBox;
    private IBurpExtenderCallbacks callbacks;
    private JButton openButton;
    private final JFileChooser fc = new JFileChooser();
    private JPanel tabPanel;

    BaseParser(IBurpExtenderCallbacks callbacks){
        this.callbacks = callbacks;
        tabPanel = new JPanel(new GridLayout(0,1));
        openButton = new JButton("Open Bruteforce output file...");
        openButton.addActionListener(this);
        tabPanel.add(openButton);
        JPanel optionsPanel = new JPanel();
        this.followRedirectsCheckBox = new JCheckBox("Follow Redirects");
        this.makeRequestsCheckBox = new JCheckBox("Make Web Requests");
        optionsPanel.add(makeRequestsCheckBox);
        optionsPanel.add(followRedirectsCheckBox);
        tabPanel.add(optionsPanel);
        tabPanel.add(new JSeparator(SwingConstants.HORIZONTAL));
        add(tabPanel);
    }

    /***
     * Gets the tabs panel so extending classes can add their options to it
     * @return JPanel
     */
    JPanel getTabPanel() {
        return tabPanel;
    }

    /**
     * Returns the burp callback class
     * @return reference to burp callback class
     */
    private IBurpExtenderCallbacks getCallbacks(){
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

    /***
     * This method is implemented by extending classes to display options to the user on how to
     * configure parsing the brute-force output
     * @return Jpanel containing option elements
     */
    abstract JPanel buildOptionsPanel();

    /***
     * Intake method to take each line of output from the brute force tool, pass it to parseDirectory
     * and creates a burp object from the returned URL.
     * @param urlString line of output from brute force tool
     * @return HttpRequestResponse created from the URL
     * @throws MalformedURLException
     */
    private HttpRequestResponse generateRequestResponse(String urlString)
            throws MalformedURLException{
        URL url = parseDirectory(urlString);
        HttpRequestResponse reqResp = new HttpRequestResponse();
        byte[] httpRequest = this.getCallbacks().getHelpers()
                .buildHttpRequest(url);
        reqResp.setRequest(httpRequest);
        int port = url.getPort();
        if (port == -1) { port = url.getDefaultPort(); }
        reqResp.setHttpService(this.getCallbacks().getHelpers()
                .buildHttpService(
                        url.getHost(),
                        port,
                        url.getProtocol().equals("https")));
        return reqResp;
    }

    private IHttpRequestResponse followRedirects(IHttpRequestResponse initial, int depth) {
        if(depth != 3) {
            IResponseInfo response = callbacks.getHelpers().analyzeResponse(initial.getResponse());
            if (response.getStatusCode() == 301 || response.getStatusCode() == 302) {
                for (String header : response.getHeaders()) {
                    if (header.trim().startsWith("Location")) {
                        HttpRequestResponse newRequest;
                        try {
                            String location = header.split("Location:")[1].trim();
                            if(location.startsWith("http")) {
                                newRequest = generateRequestResponse(location);
                            } else {
                                newRequest = generateRequestResponse(
                                        initial.getHttpService().getProtocol()
                                                +"://"+initial.getHttpService().getHost()
                                                +"/"+location);
                            }

                            IHttpRequestResponse request = callbacks.makeHttpRequest(newRequest.getHttpService(),
                                    newRequest.getRequest());
                            this.callbacks.addToSiteMap(request);
                            followRedirects(request, depth + 1);
                        } catch (MalformedURLException ex) {
                            ex.printStackTrace();
                        }
                    }
                }
            }
        }
        return initial;
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
                        try {
                            HttpRequestResponse requestResponse
                                = this.generateRequestResponse(st);
                            System.out.println(requestResponse.getHttpService().getHost());
                            System.out.println(requestResponse.getHttpService().getPort());
                            Runnable task = () -> {
                                if(makeRequestsCheckBox.isSelected()) {
                                    IHttpRequestResponse request = callbacks.makeHttpRequest(
                                            requestResponse.getHttpService(),
                                            requestResponse.getRequest());
                                    if (followRedirectsCheckBox.isSelected()) {
                                        IHttpRequestResponse response = followRedirects(request, 0);
                                        callbacks.addToSiteMap(response);
                                    } else {
                                        this.callbacks.addToSiteMap(
                                                this.callbacks.makeHttpRequest(
                                                        requestResponse.getHttpService(),
                                                        requestResponse.getRequest()));
                                    }
                                } else {
                                    this.callbacks.addToSiteMap(requestResponse);
                                }
                            };
                            new Thread(task).start();
                        } catch (MalformedURLException ex) {
                            ex.printStackTrace();
                        }
                    }
                    JOptionPane.showMessageDialog(BaseParser.this, "Successfully imported!",
                            "Directory Importer", JOptionPane.INFORMATION_MESSAGE);
                } catch (IOException ex) {
                    try {
                        JOptionPane.showMessageDialog(BaseParser.this, "Error while importing.",
                                "Directory Importer", JOptionPane.INFORMATION_MESSAGE);
                        this.callbacks.getStderr().write(ex.getMessage().getBytes());
                    } catch (IOException exc) {
                        this.callbacks.unloadExtension();
                    }
                }
            }
        }
    }
}
