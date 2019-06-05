package burp;

import parsers.GoBusterParser;

import javax.swing.*;
import java.awt.*;

/***
 * This class is the top level panel for BurpSuite. Any new parsers should be
 * added to tabbedPane
 */
class ImporterPanel extends JPanel {

    ImporterPanel(IBurpExtenderCallbacks callbacks){
        super(new GridLayout(1, 1));
        JTabbedPane tabbedPane = new JTabbedPane();
        tabbedPane.addTab("GoBuster", new GoBusterParser(callbacks));
        add(tabbedPane);

    }

}
