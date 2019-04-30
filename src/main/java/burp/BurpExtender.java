package burp;

import com.intellij.uiDesigner.core.GridConstraints;
import com.intellij.uiDesigner.core.GridLayoutManager;
import com.intellij.uiDesigner.core.Spacer;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;
import java.io.PrintWriter;
import java.util.HashMap;
import java.util.function.Predicate;
import java.util.stream.Stream;

public class BurpExtender implements IBurpExtender, ITab, IHttpListener {

    private IExtensionHelpers helpers;
    private PrintWriter pw;
    private JPanel panel;
    private JTextField apiKey;
    private JTextField apiSecret;

    private JComboBox profileComboBox;
    private int numProfiles = 0;
    private JButton saveProfileButton;
    private JButton useProfileButton;
    private JButton deleteProfileButton;
    private boolean justDeleted = false;
    private HashMap<Integer, String[]> profiles;
    private int API_KEY = 0;
    private int API_SECRET = 1;

    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {

        helpers = callbacks.getHelpers();
        this.pw = new PrintWriter(callbacks.getStdout(), true);


        setupTab();

        callbacks.setExtensionName("Mashery Signer");

        callbacks.registerContextMenuFactory(new Menu());

        SwingUtilities.invokeLater(() -> {

            callbacks.customizeUiComponent(panel);

            callbacks.addSuiteTab(BurpExtender.this);

            callbacks.registerHttpListener(BurpExtender.this);
        });


    }

    public void createNewProfile() {

        // Add another profile to the combo box, or add the add profile button if it's not already there.
        int boxSize = profileComboBox.getItemCount();
        if (boxSize == 0) {

            // If there's nothing here, just add our add profile button
            this.profileComboBox.addItem(new MasherySignerMenuItem("Add Profile", 0));
        } else {

            // If there is already an add profile button, start creating profiles
            numProfiles++;
            profileComboBox.insertItemAt(new MasherySignerMenuItem("Profile " + numProfiles, numProfiles), boxSize - 1);
            profiles.put(numProfiles, new String[]{"", ""});
            profileComboBox.setSelectedIndex(boxSize - 1);
            clearProfile();

            setMenuItems();
        }
    }

    public void clearProfile() {
        // Reset text fields
        this.apiKey.setText("");
        this.apiSecret.setText("");
    }

    public void populateProfile(int profile) {
        this.apiKey.setText(this.profiles.get(profile)[API_KEY]);
        this.apiSecret.setText(this.profiles.get(profile)[API_SECRET]);
    }

    public void setupTab() {
        // Set up profiles combobox
        this.profiles = new HashMap<Integer, String[]>();

        createNewProfile();
        // For "new profile" menu item
        createNewProfile();

        this.profileComboBox.addItemListener(new ItemListener() {
            @Override
            public void itemStateChanged(ItemEvent e) {
                if (e.getStateChange() == ItemEvent.SELECTED && !justDeleted) {
                    int selectedProfile = ((MasherySignerMenuItem) e.getItem()).getProfileNumber();
                    if (selectedProfile == 0) {
                        pw.println("Creating new profile...");
                        createNewProfile();
                    } else {
                        populateProfile(selectedProfile);
                    }
                }
            }
        });

        this.saveProfileButton.addMouseListener(new MouseListener() {
            @Override
            public void mouseClicked(MouseEvent e) {

            }

            @Override
            public void mousePressed(MouseEvent e) {

            }

            @Override
            public void mouseReleased(MouseEvent e) {
                int profile = ((MasherySignerMenuItem) profileComboBox.getSelectedItem()).getProfileNumber();
                pw.println("Saved profile " + profile + " with key: " + apiKey.getText());
                profiles.put(profile,
                        new String[]{apiKey.getText(),
                                apiSecret.getText()});
            }

            @Override
            public void mouseEntered(MouseEvent e) {

            }

            @Override
            public void mouseExited(MouseEvent e) {

            }
        });

        this.deleteProfileButton.addMouseListener(new MouseListener() {
            @Override
            public void mouseClicked(MouseEvent e) {

            }

            @Override
            public void mousePressed(MouseEvent e) {

            }

            @Override
            public void mouseReleased(MouseEvent e) {
                int profile = ((MasherySignerMenuItem) profileComboBox.getSelectedItem()).getProfileNumber();
                int index = profileComboBox.getSelectedIndex();
                pw.println("Deleting profile " + profile + "...");

                // We need to know this so that when a new item is selected by default by
                // the combobox, we can ignore the action.
                justDeleted = true;
                profileComboBox.removeItemAt(index);
                profiles.remove(profile);

                // Determine how we should move our combobox, and what profile we need to populate
                if (profiles.size() > index) {

                    // There are profiles after this one, move to the newer profile
                    profileComboBox.setSelectedIndex(index);
                    int newProfile = ((MasherySignerMenuItem) profileComboBox.getSelectedItem()).getProfileNumber();
                    populateProfile(newProfile);
                } else if (profiles.size() > 0) {

                    // No newer profiles, but there are older ones. Move to the older one
                    profileComboBox.setSelectedIndex(index - 1);
                    int newProfile = ((MasherySignerMenuItem) profileComboBox.getSelectedItem()).getProfileNumber();
                    populateProfile(newProfile);
                } else {

                    // No other profiles exist, create a new one
                    createNewProfile();
                }

                // If we just deleted our enabled profile, disable the signer
                if (profile == Menu.getEnabledProfile()) {
                    Menu.setEnabledProfile(0);
                }

                setMenuItems();

                justDeleted = false;
            }

            @Override
            public void mouseEntered(MouseEvent e) {

            }

            @Override
            public void mouseExited(MouseEvent e) {

            }
        });

        this.useProfileButton.addMouseListener(new MouseListener() {
            @Override
            public void mouseClicked(MouseEvent e) {

            }

            @Override
            public void mousePressed(MouseEvent e) {

            }

            @Override
            public void mouseReleased(MouseEvent e) {
                int profile = ((MasherySignerMenuItem) profileComboBox.getSelectedItem()).getProfileNumber();
                Menu.setEnabledProfile(profile);
            }

            @Override
            public void mouseEntered(MouseEvent e) {

            }

            @Override
            public void mouseExited(MouseEvent e) {

            }
        });
    }

    // Set the menu items in the context menu
    private void setMenuItems() {
        int itemCount = profileComboBox.getItemCount();
        MasherySignerMenuItem[] menuItems = new MasherySignerMenuItem[itemCount - 1];

        // Skip the first item, it's just the add profile button
        for (int i = 0; i < itemCount - 1; i++) {
            menuItems[i] = (MasherySignerMenuItem) profileComboBox.getItemAt(i);
        }

        Menu.setMenuItems(menuItems);
    }

    @Override
    public String getTabCaption() {
        return "Mashery Signer";
    }

    @Override
    public Component getUiComponent() {
        return panel;
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) throws Exception {

        if(messageIsRequest) {
            if (Menu.getEnabledProfile() > 0) {
                IRequestInfo request = helpers.analyzeRequest(messageInfo.getRequest());

                java.util.List<IParameter> params = request.getParameters();
                Stream<IParameter> ps = params.stream();

                Predicate<IParameter> onlyUrl = param -> (param.getType() == IParameter.PARAM_URL);
                Predicate<IParameter> namedParams = param -> (param.getName().equals("api_key") || param.getName().equals("sig")); ;

                if (ps.filter(onlyUrl).anyMatch(namedParams)) {
                    String[] profile = this.profiles.get(Menu.getEnabledProfile());
                    pw.println("Signing with profile " + Menu.getEnabledProfile() + " with key: " + profile[API_KEY]);
                    byte[] signedRequest = Utility.signRequest(messageInfo,
                            helpers,
                            profile[API_KEY],
                            profile[API_SECRET]);
                    pw.println(signedRequest.toString());
                    messageInfo.setRequest(signedRequest);

                }
            }
        }

    }

    {
// GUI initializer generated by IntelliJ IDEA GUI Designer
// >>> IMPORTANT!! <<<
// DO NOT EDIT OR ADD ANY CODE HERE!
        $$$setupUI$$$();
    }

    /**
     * Method generated by IntelliJ IDEA GUI Designer
     * >>> IMPORTANT!! <<<
     * DO NOT edit this method OR call it in your code!
     *
     * @noinspection ALL
     */
    private void $$$setupUI$$$() {
        panel = new JPanel();
        panel.setLayout(new GridLayoutManager(7, 2, new Insets(0, 0, 0, 0), -1, -1));
        final JLabel label1 = new JLabel();
        label1.setText("Access Key: ");
        panel.add(label1, new GridConstraints(1, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        apiKey = new JTextField();
        panel.add(apiKey, new GridConstraints(1, 1, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        final JLabel label2 = new JLabel();
        label2.setText("Secret Key:");
        panel.add(label2, new GridConstraints(2, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        apiSecret = new JTextField();
        panel.add(apiSecret, new GridConstraints(2, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        final Spacer spacer1 = new Spacer();
        panel.add(spacer1, new GridConstraints(6, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_VERTICAL, 1, GridConstraints.SIZEPOLICY_WANT_GROW, null, null, null, 0, false));
        final JLabel label5 = new JLabel();
        label5.setText("Profile:");
        panel.add(label5, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        profileComboBox = new JComboBox();
        final DefaultComboBoxModel defaultComboBoxModel1 = new DefaultComboBoxModel();
        profileComboBox.setModel(defaultComboBoxModel1);
        panel.add(profileComboBox, new GridConstraints(0, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        saveProfileButton = new JButton();
        saveProfileButton.setText("Save Profile");
        panel.add(saveProfileButton, new GridConstraints(5, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JPanel panel1 = new JPanel();
        panel1.setLayout(new GridLayoutManager(1, 1, new Insets(0, 0, 0, 0), -1, -1));
        panel.add(panel1, new GridConstraints(6, 1, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        final JPanel panel2 = new JPanel();
        panel2.setLayout(new GridLayoutManager(1, 2, new Insets(0, 0, 0, 0), -1, -1));
        panel.add(panel2, new GridConstraints(5, 1, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        deleteProfileButton = new JButton();
        deleteProfileButton.setText("Delete Profile");
        panel2.add(deleteProfileButton, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, 1, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        useProfileButton = new JButton();
        useProfileButton.setText("Use Profile");
        panel2.add(useProfileButton, new GridConstraints(0, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
    }

    /**
     * @noinspection ALL
     */
    public JComponent $$$getRootComponent$$$() {
        return panel;
    }
}
