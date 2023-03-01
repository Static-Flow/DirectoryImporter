package parsers;

import burp.IBurpExtenderCallbacks;

import javax.swing.*;
import java.awt.*;
import java.net.MalformedURLException;
import java.net.URL;

public class FlatParser extends BaseParser {

    private JTextField domainTextField;

    public FlatParser(IBurpExtenderCallbacks callbacks) {
        super(callbacks);
        getTabPanel().add(buildOptionsPanel());
    }

    @Override
    URL parseDirectory(String urlString) throws MalformedURLException {
        return new URL(this.domainTextField.getText()+urlString);
    }

    @Override
    JPanel buildOptionsPanel() {
        JPanel optionsPanel = new JPanel(new GridLayout(0,1));
        optionsPanel.add(new JLabel("Enter the domain if your flat file contains only paths."));
        this.domainTextField = new JTextField();
        optionsPanel.add(this.domainTextField);
        return optionsPanel;
    }
}
