package burp;

import parsers.GoBusterParser;

import javax.swing.*;
import java.awt.*;

class ImporterPanel extends JPanel {

    ImporterPanel(IBurpExtenderCallbacks callbacks){
        super(new GridLayout(1, 1));
        JTabbedPane tabbedPane = new JTabbedPane();
        tabbedPane.addTab("GoBuster", new GoBusterParser(callbacks));
        add(tabbedPane);

    }

}
