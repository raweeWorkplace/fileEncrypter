/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package application;

import java.awt.Toolkit;
import java.awt.event.WindowEvent;
import java.io.File;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.ButtonGroup;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;

/**
 *
 * @author idiotbox
 */
public class mainApplicaton extends javax.swing.JFrame {
    private final JTextField filename = new JTextField(), dir = new JTextField();
    protected String plainFilePath = null;
    protected File plainFile = null;
    private PublicKey publicKeyRSA;
    private PrivateKey privateKeyRSA;
    private SecretKeySpec publicKeyDES;
    private int size;
    /**
     * Creates new form mainApplicaton
     */
    public mainApplicaton() {
        initComponents();
        this.setLocationRelativeTo(null);
        buttonGroup();
        EncryptionRadio.setSelected(true);
    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jLabel3 = new javax.swing.JLabel();
        basePanel = new javax.swing.JPanel();
        headPanel = new javax.swing.JPanel();
        jLabel1 = new javax.swing.JLabel();
        lblClose = new javax.swing.JLabel();
        jLabel2 = new javax.swing.JLabel();
        EncryptionRadio = new javax.swing.JRadioButton();
        DecryptionRadio = new javax.swing.JRadioButton();
        operationPanel = new javax.swing.JPanel();
        jLabel4 = new javax.swing.JLabel();
        btnBrowse = new javax.swing.JButton();
        lblFileName = new javax.swing.JLabel();
        jLabel5 = new javax.swing.JLabel();
        EncryptionTypeCombo = new javax.swing.JComboBox<>();
        jLabel6 = new javax.swing.JLabel();
        EncryptionMethodCombo = new javax.swing.JComboBox<>();
        submitButton = new javax.swing.JButton();
        lblTimeTaken = new javax.swing.JLabel();
        lblStoredFileLocation = new javax.swing.JLabel();

        jLabel3.setText("jLabel3");

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);
        setUndecorated(true);
        setResizable(false);

        basePanel.setBackground(java.awt.Color.white);

        headPanel.setBackground(new java.awt.Color(253, 88, 136));

        jLabel1.setFont(new java.awt.Font("Asana Math", 1, 36)); // NOI18N
        jLabel1.setForeground(java.awt.Color.white);
        jLabel1.setText("ENCRYPTION APPLICATION");

        lblClose.setIcon(new javax.swing.ImageIcon(getClass().getResource("/application/delete-filled.png"))); // NOI18N
        lblClose.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                lblCloseMouseClicked(evt);
            }
        });

        javax.swing.GroupLayout headPanelLayout = new javax.swing.GroupLayout(headPanel);
        headPanel.setLayout(headPanelLayout);
        headPanelLayout.setHorizontalGroup(
            headPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(headPanelLayout.createSequentialGroup()
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addComponent(jLabel1)
                .addGap(106, 106, 106)
                .addComponent(lblClose)
                .addContainerGap())
        );
        headPanelLayout.setVerticalGroup(
            headPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(headPanelLayout.createSequentialGroup()
                .addGroup(headPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(headPanelLayout.createSequentialGroup()
                        .addContainerGap()
                        .addComponent(lblClose))
                    .addGroup(headPanelLayout.createSequentialGroup()
                        .addGap(24, 24, 24)
                        .addComponent(jLabel1)))
                .addContainerGap(26, Short.MAX_VALUE))
        );

        jLabel2.setFont(new java.awt.Font("Bitstream Vera Serif", 0, 18)); // NOI18N
        jLabel2.setText("Operation :");

        EncryptionRadio.setFont(new java.awt.Font("Bitstream Vera Serif", 0, 18)); // NOI18N
        EncryptionRadio.setText("Encryption");

        DecryptionRadio.setFont(new java.awt.Font("Bitstream Vera Serif", 0, 18)); // NOI18N
        DecryptionRadio.setText("Decryption");

        operationPanel.setBackground(new java.awt.Color(254, 195, 136));

        jLabel4.setFont(new java.awt.Font("Bitstream Vera Serif", 0, 18)); // NOI18N
        jLabel4.setForeground(java.awt.Color.darkGray);
        jLabel4.setText("Select File :");

        btnBrowse.setFont(new java.awt.Font("Bitstream Vera Serif", 0, 18)); // NOI18N
        btnBrowse.setText("Browse File...");
        btnBrowse.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnBrowseActionPerformed(evt);
            }
        });

        lblFileName.setFont(new java.awt.Font("Bitstream Vera Serif", 0, 18)); // NOI18N

        jLabel5.setFont(new java.awt.Font("Bitstream Vera Serif", 0, 18)); // NOI18N
        jLabel5.setForeground(java.awt.Color.darkGray);
        jLabel5.setText("Encryption Type :");

        EncryptionTypeCombo.setFont(new java.awt.Font("Bitstream Vera Serif", 0, 18)); // NOI18N
        EncryptionTypeCombo.setModel(new javax.swing.DefaultComboBoxModel<>(new String[] { "Normal", "Sensitive" }));
        EncryptionTypeCombo.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                EncryptionTypeComboActionPerformed(evt);
            }
        });

        jLabel6.setFont(new java.awt.Font("Bitstream Vera Serif", 0, 18)); // NOI18N
        jLabel6.setForeground(java.awt.Color.darkGray);
        jLabel6.setText("Encryption Method :");

        EncryptionMethodCombo.setFont(new java.awt.Font("Bitstream Vera Serif", 0, 18)); // NOI18N
        EncryptionMethodCombo.addFocusListener(new java.awt.event.FocusAdapter() {
            public void focusGained(java.awt.event.FocusEvent evt) {
                EncryptionMethodComboFocusGained(evt);
            }
        });

        submitButton.setFont(new java.awt.Font("Bitstream Vera Serif", 0, 18)); // NOI18N
        submitButton.setText("Submit");
        submitButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                submitButtonActionPerformed(evt);
            }
        });

        lblTimeTaken.setFont(new java.awt.Font("Bitstream Vera Serif", 0, 18)); // NOI18N

        lblStoredFileLocation.setFont(new java.awt.Font("Bitstream Vera Serif", 0, 18)); // NOI18N

        javax.swing.GroupLayout operationPanelLayout = new javax.swing.GroupLayout(operationPanel);
        operationPanel.setLayout(operationPanelLayout);
        operationPanelLayout.setHorizontalGroup(
            operationPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, operationPanelLayout.createSequentialGroup()
                .addContainerGap(155, Short.MAX_VALUE)
                .addGroup(operationPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(operationPanelLayout.createSequentialGroup()
                        .addGap(80, 80, 80)
                        .addComponent(jLabel4)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(btnBrowse, javax.swing.GroupLayout.PREFERRED_SIZE, 167, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addGroup(operationPanelLayout.createSequentialGroup()
                        .addGroup(operationPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                            .addComponent(jLabel5)
                            .addComponent(jLabel6))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addGroup(operationPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(lblFileName, javax.swing.GroupLayout.PREFERRED_SIZE, 305, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addGroup(operationPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                                .addComponent(submitButton, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                .addComponent(EncryptionMethodCombo, javax.swing.GroupLayout.PREFERRED_SIZE, 127, javax.swing.GroupLayout.PREFERRED_SIZE))
                            .addComponent(lblTimeTaken, javax.swing.GroupLayout.PREFERRED_SIZE, 253, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(EncryptionTypeCombo, javax.swing.GroupLayout.PREFERRED_SIZE, 156, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(lblStoredFileLocation, javax.swing.GroupLayout.PREFERRED_SIZE, 253, javax.swing.GroupLayout.PREFERRED_SIZE))))
                .addGap(139, 139, 139))
        );

        operationPanelLayout.linkSize(javax.swing.SwingConstants.HORIZONTAL, new java.awt.Component[] {EncryptionMethodCombo, EncryptionTypeCombo, btnBrowse});

        operationPanelLayout.setVerticalGroup(
            operationPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(operationPanelLayout.createSequentialGroup()
                .addGap(29, 29, 29)
                .addGroup(operationPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel4)
                    .addComponent(btnBrowse))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(lblFileName, javax.swing.GroupLayout.PREFERRED_SIZE, 26, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(operationPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(EncryptionTypeCombo, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel5))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(operationPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(EncryptionMethodCombo, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel6))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(submitButton, javax.swing.GroupLayout.PREFERRED_SIZE, 45, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(lblTimeTaken, javax.swing.GroupLayout.PREFERRED_SIZE, 35, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addComponent(lblStoredFileLocation, javax.swing.GroupLayout.PREFERRED_SIZE, 35, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap())
        );

        operationPanelLayout.linkSize(javax.swing.SwingConstants.VERTICAL, new java.awt.Component[] {EncryptionMethodCombo, EncryptionTypeCombo, btnBrowse, jLabel4, jLabel5, jLabel6, lblFileName});

        javax.swing.GroupLayout basePanelLayout = new javax.swing.GroupLayout(basePanel);
        basePanel.setLayout(basePanelLayout);
        basePanelLayout.setHorizontalGroup(
            basePanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(basePanelLayout.createSequentialGroup()
                .addGroup(basePanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING, false)
                    .addComponent(operationPanel, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(headPanel, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                .addGap(0, 0, Short.MAX_VALUE))
            .addGroup(basePanelLayout.createSequentialGroup()
                .addGap(92, 92, 92)
                .addComponent(jLabel2)
                .addGap(129, 129, 129)
                .addComponent(EncryptionRadio)
                .addGap(94, 94, 94)
                .addComponent(DecryptionRadio)
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );
        basePanelLayout.setVerticalGroup(
            basePanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(basePanelLayout.createSequentialGroup()
                .addComponent(headPanel, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(basePanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel2)
                    .addComponent(EncryptionRadio)
                    .addComponent(DecryptionRadio))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(operationPanel, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(basePanel, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(basePanel, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    
    private void buttonGroup(){
        ButtonGroup bg = new ButtonGroup();
        bg.add(EncryptionRadio);
        bg.add(DecryptionRadio);
    }
    
    private void reset(){
       plainFile = null;
       plainFilePath = null;
       lblFileName.setText("");
       lblTimeTaken.setText("");
       publicKeyRSA = null;
       privateKeyRSA = null;
       EncryptionRadio.setSelected(true);
       size = 0;
    }
    
    
    private void fillComboMethod(){
        int index =-1;
        index = EncryptionTypeCombo.getSelectedIndex();
        EncryptionMethodCombo.removeAllItems();
        if(index==0){
            
            EncryptionMethodCombo.addItem("SHA1");
            EncryptionMethodCombo.addItem("MD5");
        }else{
            EncryptionMethodCombo.addItem("AES");
            EncryptionMethodCombo.addItem("DES");
            EncryptionMethodCombo.addItem("BlowFish");
        }
    }
    
    private void encType(int ciphermode, Key accessKey, SecretKeySpec secKey){
        JFileChooser c = new JFileChooser();
        int rVal = c.showSaveDialog(this);
        String operation = "";
        operation = EncryptionMethodCombo.getSelectedItem().toString();
        if (rVal == JFileChooser.APPROVE_OPTION) {
        filename.setText(c.getSelectedFile().getName());
        dir.setText(c.getCurrentDirectory().toString());
        plainFilePath = dir.getText()+"/"+filename.getText();
        
        if (plainFilePath != null){
            long startTime; 
            long endTime;   
            double time;   
         
        startTime = System.currentTimeMillis();
	
                if(operation.equalsIgnoreCase("AES")){
                    String key = "This is a secret";
                    Crypto.fileProcessorAES(ciphermode, key, plainFile, new File(plainFilePath));
                }else if(operation.equalsIgnoreCase("DES")){
                    Crypto.fileProcessorDES(ciphermode, secKey, plainFile, new File(plainFilePath));
                }else if(operation.equalsIgnoreCase("SHA1")){
                    Crypto.fileProcessorSHA(plainFile, new File(plainFilePath));
                }else if(operation.equalsIgnoreCase("MD5")){
                    Crypto.fileProcessorMD5(plainFile, new File(plainFilePath));
                }else if(operation.equalsIgnoreCase("BlowFish")){
                    String keyString = "DesireSecretKey";
                    Crypto.fileProcessorBlowFish(ciphermode, keyString, plainFile, new File(plainFilePath));
                }
                            
            endTime = System.currentTimeMillis();
            time = (endTime - startTime) / 1000.0;
            lblTimeTaken.setText("Encryption Time ; " +Double.toString(time));
            lblStoredFileLocation.setText(plainFilePath);
        }
      }
      if (rVal == JFileChooser.CANCEL_OPTION) {
        filename.setText("You pressed cancel");
        dir.setText("");
        
      }
    }
    private void btnBrowseActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnBrowseActionPerformed
        JFileChooser plainFileChooser = new JFileChooser();
        int rVal = plainFileChooser.showSaveDialog(this);
        if (rVal == JFileChooser.APPROVE_OPTION) {
            plainFile = plainFileChooser.getSelectedFile();
            size = (int) plainFile.length() / 1024;
            lblFileName.setText(plainFileChooser.getSelectedFile().getName()+"  "+size+ "  kb");
        }
        if (rVal == JFileChooser.CANCEL_OPTION) {
            filename.setText("You pressed cancel");
            dir.setText("");
        }
    }//GEN-LAST:event_btnBrowseActionPerformed

    private void lblCloseMouseClicked(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_lblCloseMouseClicked
        this.setDefaultCloseOperation(EXIT_ON_CLOSE);
        WindowEvent winClosingEvent = new WindowEvent(SwingUtilities.getWindowAncestor(basePanel), WindowEvent.WINDOW_CLOSING);
        Toolkit.getDefaultToolkit().getSystemEventQueue().postEvent(winClosingEvent);
    }//GEN-LAST:event_lblCloseMouseClicked

    private void EncryptionMethodComboFocusGained(java.awt.event.FocusEvent evt) {//GEN-FIRST:event_EncryptionMethodComboFocusGained
        
    }//GEN-LAST:event_EncryptionMethodComboFocusGained

    private void EncryptionTypeComboActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_EncryptionTypeComboActionPerformed
        fillComboMethod();
    }//GEN-LAST:event_EncryptionTypeComboActionPerformed

    private void submitButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_submitButtonActionPerformed
        if(EncryptionRadio.isSelected()){
            if(EncryptionMethodCombo.getSelectedItem().toString().equalsIgnoreCase("DES")){
                encType(Cipher.ENCRYPT_MODE,null,publicKeyDES);
                String key64 = Base64.getEncoder().encodeToString(publicKeyDES.getEncoded());
                JOptionPane.showMessageDialog(null, new JTextArea(key64), "Private Key", JOptionPane.INFORMATION_MESSAGE);
        }else{
            encType(Cipher.ENCRYPT_MODE, null, null);
        }
        }else{
            if(EncryptionMethodCombo.getSelectedItem().toString().equalsIgnoreCase("DES")){
                String keyString = JOptionPane.showInputDialog("Enter Private Key");
                byte[] decodedKey = Base64.getDecoder().decode(keyString);
                SecretKeySpec key = new SecretKeySpec(decodedKey, 0, decodedKey.length, "DES");
                encType(Cipher.DECRYPT_MODE,null,key);
        }else{
            encType(Cipher.DECRYPT_MODE, null, null);
        }
        }
        reset();
    }//GEN-LAST:event_submitButtonActionPerformed

    /**
     * @param args the command line arguments
     */
    public static void main(String args[]) {
        /* Set the Nimbus look and feel */
        //<editor-fold defaultstate="collapsed" desc=" Look and feel setting code (optional) ">
        /* If Nimbus (introduced in Java SE 6) is not available, stay with the default look and feel.
         * For details see http://download.oracle.com/javase/tutorial/uiswing/lookandfeel/plaf.html 
         */
        try {
            for (javax.swing.UIManager.LookAndFeelInfo info : javax.swing.UIManager.getInstalledLookAndFeels()) {
                if ("Nimbus".equals(info.getName())) {
                    javax.swing.UIManager.setLookAndFeel(info.getClassName());
                    break;
                }
            }
        } catch (ClassNotFoundException ex) {
            java.util.logging.Logger.getLogger(mainApplicaton.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (InstantiationException ex) {
            java.util.logging.Logger.getLogger(mainApplicaton.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (IllegalAccessException ex) {
            java.util.logging.Logger.getLogger(mainApplicaton.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (javax.swing.UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(mainApplicaton.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }
        //</editor-fold>

        /* Create and display the form */
        java.awt.EventQueue.invokeLater(new Runnable() {
            public void run() {
                new mainApplicaton().setVisible(true);
            }
        });
    }

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JRadioButton DecryptionRadio;
    private javax.swing.JComboBox<String> EncryptionMethodCombo;
    private javax.swing.JRadioButton EncryptionRadio;
    private javax.swing.JComboBox<String> EncryptionTypeCombo;
    private javax.swing.JPanel basePanel;
    private javax.swing.JButton btnBrowse;
    private javax.swing.JPanel headPanel;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JLabel jLabel4;
    private javax.swing.JLabel jLabel5;
    private javax.swing.JLabel jLabel6;
    private javax.swing.JLabel lblClose;
    private javax.swing.JLabel lblFileName;
    private javax.swing.JLabel lblStoredFileLocation;
    private javax.swing.JLabel lblTimeTaken;
    private javax.swing.JPanel operationPanel;
    private javax.swing.JButton submitButton;
    // End of variables declaration//GEN-END:variables
}
