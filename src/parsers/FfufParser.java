package parsers;

import burp.IBurpExtenderCallbacks;

import javax.swing.*;
import java.awt.*;
import java.net.MalformedURLException;
import java.net.URL;

/***
 * This parser handles output from the FFuF tool. Use the radio buttons below the file selection to
 * specify whether csv, ecsv, or md format was used to output the results.
 */
public class FfufParser extends BaseParser {
    private JPanel optionPanel;
    public FfufParser(IBurpExtenderCallbacks callbacks) {
        super(callbacks);
        optionPanel = buildOptionsPanel();
        getTabPanel().add(optionPanel);
    }

    /***
     * This is slightly more complex since there are multiple output formats: csv, ecsv, html, and md
     * json and ejson aren't supported (yet). Sorry.
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
                    if(radioButton.getText().equalsIgnoreCase("md")){
                        if (urlString.contains(" | ")) {
                            return new URL(urlString.split(" \\| ")[2]);
                        }
                    } else if(radioButton.getText().equalsIgnoreCase("csv")
                        | radioButton.getText().equalsIgnoreCase("ecsv")){
                        return new URL(urlString.split(",")[1]);
                    } else if(radioButton.getText().equalsIgnoreCase("html")) {
                        // check that line is a URL
                        if (urlString.matches(".*<td><a href=\".*\">.*</a></td>")) {
                            int start = urlString.indexOf("<td>") + "<td><a href=\"".length();
                            int end = urlString.indexOf("\"", start);
                            return new URL(urlString.substring(start, end));
                        }
                    }
                }
            }
        }
        return new URL("");
    }

    /***
     * This builds the option menu for FFuF. It contains radio buttons to determine how to parse the output
     * @return JPanel containing the options
     */
    @Override
    JPanel buildOptionsPanel() {
        String[] outputTypes = {"md", "csv", "ecsv", "html"};
        JPanel optionsPanel = new JPanel(new GridLayout(0,1));
        optionsPanel.add(new JLabel("Please specify which output mode you used when running Ffuf"));
        ButtonGroup ffufOutputTypeGroup = new ButtonGroup();
        for(String outputType : outputTypes) {
            JRadioButton outputTypeButton = new JRadioButton(outputType);
            ffufOutputTypeGroup.add(outputTypeButton);
            optionsPanel.add(outputTypeButton);
        }
        return optionsPanel;
    }
}
