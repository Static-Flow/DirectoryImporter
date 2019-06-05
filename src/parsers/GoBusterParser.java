package parsers;

import burp.IBurpExtenderCallbacks;

import javax.swing.*;
import java.awt.*;
import java.net.MalformedURLException;
import java.net.URL;

/***
 * This parser handles output from the GoBuster tool. It expects you to run it
 * with the -e flag so the whole url is there and not just the path.
 */
public class GoBusterParser extends BaseParser {
    private JTextField domainTextField;

    public GoBusterParser(IBurpExtenderCallbacks callbacks){
        super(callbacks);
        getTabPanel().add(buildOptionsPanel());
    }

    /***
     * Parsing GoBuster is relatively simple, each line has a url followed by a
     * (Status: XXX) HTTP code indicator
     * @param urlString line of output containing a url
     * @return URL object for burp to process
     * @throws MalformedURLException thrown in case you mess up parsing it
     */
    @Override
    URL parseDirectory(String urlString) throws MalformedURLException {
        return new URL(this.domainTextField.getText()+urlString.split(" \\(")[0]);
    }

    /***
     * Implemented method for displaying options on configuring output parsing
     * See DirSearchParser for a more fleshed out example
     * @return Jpanel containing options
     */
    @Override
    JPanel buildOptionsPanel() {
        JPanel optionsPanel = new JPanel(new GridLayout(0,1));
        optionsPanel.add(new JLabel("If you did not run GoBuster with the -e flag please enter the base url you " +
                "ran it against, e.g. https://foo.com. Otherwise, leave it blank."));
        this.domainTextField = new JTextField();
        optionsPanel.add(this.domainTextField);
        return optionsPanel;
    }

}
