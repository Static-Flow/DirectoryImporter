package burp;

import java.awt.*;

public class BurpExtender
        implements IBurpExtender,
        ITab {
    private IBurpExtenderCallbacks callbacks;

    public void registerExtenderCallbacks(IBurpExtenderCallbacks iBurpExtenderCallbacks) {
        this.callbacks = iBurpExtenderCallbacks;
        this.callbacks.setExtensionName("Directory Importer");
        this.callbacks.addSuiteTab(this);

    }

    public String getTabCaption() {
        return "Directory Importer";
    }

    public Component getUiComponent() {
        return new ImporterPanel(this.callbacks);
    }
}
