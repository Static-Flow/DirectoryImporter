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

    IBurpExtenderCallbacks getCallbacks(){
        return this.callbacks;
    }

    abstract HttpRequestResponse parseDirectory(String urlString) throws MalformedURLException;


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
                                this.parseDirectory(st);
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
