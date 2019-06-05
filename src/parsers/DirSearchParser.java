package parsers;

import burp.IBurpExtenderCallbacks;

import javax.swing.*;
import java.awt.*;
import java.net.MalformedURLException;
import java.net.URL;

/***
 * This parser handles output from the Dirsearch tool. Use the radio buttons below the file selection to
 * specify whether simple-report, or plain-text-report was used to output the results.
 */
public class DirSearchParser extends BaseParser {
    private JPanel optionPanel;
    public DirSearchParser(IBurpExtenderCallbacks callbacks) {
        super(callbacks);
        optionPanel = buildOptionsPanel();
        getTabPanel().add(optionPanel);
    }

    /***
     * This is slightly more complex since there are multiple output formats, simple-report, plain-report
     * json-report isn't supported. Sorry.
     * @param urlString line of output containing a url
     * @return URL object
     * @throws MalformedURLException
     */
    @Override
    URL parseDirectory(String urlString) throws MalformedURLException {
        Component[] components = this.optionPanel.getComponents();
        for(Component component : components){
            if (component instanceof JRadioButton)
            {
                JRadioButton radioButton = (JRadioButton) component;
                if(radioButton.isSelected()){
                    if(radioButton.getText().equalsIgnoreCase("simple-report")){
                        return new URL(urlString);
                    } else if(radioButton.getText().equalsIgnoreCase("plain-text-report")){
                        return new URL(urlString.split(" {3}")[2]);
                    }
                }
            }
        }
        return new URL("");
    }

    /***
     * THe builds the option menu for Dirsearch. It contains 2 radio buttons to determine how to parse the output
     * @return JPanel containing the options
     */
    @Override
    JPanel buildOptionsPanel() {
        JPanel optionsPanel = new JPanel(new GridLayout(0,1));
        ButtonGroup dirSearchOutputTypeGroup = new ButtonGroup();
        JRadioButton simpleReport = new JRadioButton("simple-report");
        JRadioButton plainTextReport = new JRadioButton("plain-text-report");
        dirSearchOutputTypeGroup.add(simpleReport);
        dirSearchOutputTypeGroup.add(plainTextReport);
        optionsPanel.add(new JLabel("Please specify which output mode you used when running Dirsearch"));
        optionsPanel.add(simpleReport);
        optionsPanel.add(plainTextReport);
        return optionsPanel;
    }
}
