import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.Base64;

public class aaa {

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> new aaa().createGUI());
    }

    // 建立 GUI
    private void createGUI() {
        JFrame frame = new JFrame("AES & DES File Encryption Tool");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setSize(400, 400);
        frame.setLayout(new GridLayout(6, 1));

        JTextField passwordField = new JTextField();
        JButton aesEncryptButton = new JButton("AES Encrypt File/Directory");
        JButton aesDecryptButton = new JButton("AES Decrypt File/Directory");
        JButton desEncryptButton = new JButton("DES Encrypt File/Directory");
        JButton desDecryptButton = new JButton("DES Decrypt File/Directory");
        JLabel statusLabel = new JLabel("Status: Idle");

        frame.add(new JLabel("Enter Password:"));
        frame.add(passwordField);
        frame.add(aesEncryptButton);
        frame.add(aesDecryptButton);
        frame.add(desEncryptButton);
        frame.add(desDecryptButton);
        frame.add(statusLabel);

        // AES 加密 按鈕
        aesEncryptButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                handleEncryption(frame, passwordField, statusLabel, "AES", Cipher.ENCRYPT_MODE);
            }
        });

        // AES 解密 按鈕
        aesDecryptButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                handleEncryption(frame, passwordField, statusLabel, "AES", Cipher.DECRYPT_MODE);
            }
        });

        // DES 加密 按鈕
        desEncryptButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                handleEncryption(frame, passwordField, statusLabel, "DES", Cipher.ENCRYPT_MODE);
            }
        });

        // DES 解密 按鈕
        desDecryptButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                handleEncryption(frame, passwordField, statusLabel, "DES", Cipher.DECRYPT_MODE);
            }
        });

        frame.setVisible(true);
    }

    // 處理加密/解密
    private void handleEncryption(JFrame frame, JTextField passwordField, JLabel statusLabel, String algorithm, int mode) {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setFileSelectionMode(JFileChooser.FILES_AND_DIRECTORIES);
        if (fileChooser.showOpenDialog(frame) == JFileChooser.APPROVE_OPTION) {
            File file = fileChooser.getSelectedFile();
            String password = passwordField.getText();
            if (!password.isEmpty()) {
                try {
                    if (mode == Cipher.ENCRYPT_MODE) {
                        encryptFile(file, password, algorithm);
                        statusLabel.setText("Status: " + algorithm + " Encryption Completed");
                    } else {
                        decryptFile(file, password, algorithm);
                        statusLabel.setText("Status: " + algorithm + " Decryption Completed");
                    }
                } catch (Exception ex) {
                    statusLabel.setText("Status: Error during " + algorithm + " operation");
                    ex.printStackTrace();
                }
            } else {
                JOptionPane.showMessageDialog(frame, "Password cannot be empty.");
            }
        }
    }

    // 加密單一檔案
    private void encryptFile(File file, String password, String algorithm) throws Exception {
        SecretKeySpec key = generateKey(password, algorithm);
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, key);

        FileInputStream fis = new FileInputStream(file);
        byte[] inputBytes = new byte[(int) file.length()];
        fis.read(inputBytes);
        fis.close();

        byte[] outputBytes = cipher.doFinal(inputBytes);

        FileOutputStream fos = new FileOutputStream(file);
        fos.write(outputBytes);
        fos.close();
    }

    // 解密單一檔案
    private void decryptFile(File file, String password, String algorithm) throws Exception {
        SecretKeySpec key = generateKey(password, algorithm);
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.DECRYPT_MODE, key);

        FileInputStream fis = new FileInputStream(file);
        byte[] inputBytes = new byte[(int) file.length()];
        fis.read(inputBytes);
        fis.close();

        byte[] outputBytes = cipher.doFinal(inputBytes);

        FileOutputStream fos = new FileOutputStream(file);
        fos.write(outputBytes);
        fos.close();
    }

    // 生成加密金鑰
    private SecretKeySpec generateKey(String password, String algorithm) throws Exception {
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        byte[] key = password.getBytes("UTF-8");
        key = sha.digest(key);
        if (algorithm.equals("DES")) {
            // DES 金鑰長度為 8 bytes
            return new SecretKeySpec(key, 0, 8, algorithm);
        }
        // AES 金鑰長度為 16 bytes
        return new SecretKeySpec(key, 0, 16, algorithm);
    }
}
