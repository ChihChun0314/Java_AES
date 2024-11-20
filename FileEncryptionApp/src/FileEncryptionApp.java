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

public class FileEncryptionApp {

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> new FileEncryptionApp().createGUI());
    }
    // 建立 GUI
    private void createGUI() {
        JFrame frame = new JFrame("AES File Encryption Tool");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setSize(400, 300);
        frame.setLayout(new GridLayout(5, 1));

        JTextField passwordField = new JTextField();
        JButton encryptButton = new JButton("Encrypt File/Directory");
        JButton decryptButton = new JButton("Decrypt File/Directory");
        JLabel statusLabel = new JLabel("Status: Idle");

        frame.add(new JLabel("Enter Password:"));
        frame.add(passwordField);
        frame.add(encryptButton);
        frame.add(decryptButton);
        frame.add(statusLabel);

        // 加密 按鈕
        encryptButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                JFileChooser fileChooser = new JFileChooser();
                fileChooser.setFileSelectionMode(JFileChooser.FILES_AND_DIRECTORIES);
                if (fileChooser.showOpenDialog(frame) == JFileChooser.APPROVE_OPTION) {
                    File file = fileChooser.getSelectedFile();
                    String password = passwordField.getText();
                    if (!password.isEmpty()) {
                        try {
                            if (file.isDirectory()) {
                                encryptDirectory(file, password); // 加密整個目錄
                            } else {
                                encryptFile(file, password);  // 加密單個檔案
                            }
                            statusLabel.setText("Status: Encryption Completed");
                        } catch (Exception ex) {
                            statusLabel.setText("Status: Error Encrypting File/Directory");
                            ex.printStackTrace();
                        }
                    } else {
                        JOptionPane.showMessageDialog(frame, "Password cannot be empty.");
                    }
                }
            }
        });

        // 解密 按鈕
        decryptButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                JFileChooser fileChooser = new JFileChooser();
                fileChooser.setFileSelectionMode(JFileChooser.FILES_AND_DIRECTORIES);
                if (fileChooser.showOpenDialog(frame) == JFileChooser.APPROVE_OPTION) {
                    File file = fileChooser.getSelectedFile();
                    String password = passwordField.getText();
                    if (!password.isEmpty()) {
                        try {
                            if (file.isDirectory()) {
                                decryptDirectory(file, password); // 解密 目錄
                            } else {
                                decryptFile(file, password);  // 解密 單一檔案
                            }
                            statusLabel.setText("Status: Decryption Completed");
                        } catch (Exception ex) {
                            statusLabel.setText("Status: Error Decrypting File/Directory");
                            ex.printStackTrace();
                        }
                    } else {
                        JOptionPane.showMessageDialog(frame, "Password cannot be empty.");
                    }
                }
            }
        });

        frame.setVisible(true);
    }

    // 加密 單一檔案
    private void encryptFile(File file, String password) throws Exception {
        SecretKeySpec key = generateKey(password);   // 生成  加密金鑰
        Cipher cipher = Cipher.getInstance("AES"); // 使用cipher的含式庫 "AES"
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

    // 解密 單一檔案
    private void decryptFile(File file, String password) throws Exception {
        SecretKeySpec key = generateKey(password);   // 生成  解密金鑰
        Cipher cipher = Cipher.getInstance("AES");
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

    // 加密  整個目錄  的  所有檔案
    private void encryptDirectory(File directory, String password) throws Exception {
        Files.walk(directory.toPath()).filter(Files::isRegularFile).forEach(path -> {
            try {
                encryptFile(path.toFile(), password);  // 對目錄中的每個檔案進行加密
            } catch (Exception e) {
                e.printStackTrace();
            }
        });
    }

    // 解密  整個目錄  的  所有檔案
    private void decryptDirectory(File directory, String password) throws Exception {
        Files.walk(directory.toPath()).filter(Files::isRegularFile).forEach(path -> {
            try {
                decryptFile(path.toFile(), password); // 對目錄中的每個檔案進行解密
            } catch (Exception e) {
                e.printStackTrace();
            }
        });
    }

    // 生成 AES 加密金鑰
    private SecretKeySpec generateKey(String password) throws Exception {
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        byte[] key = password.getBytes("UTF-8");
        key = sha.digest(key);
        return new SecretKeySpec(key, "AES");
    }
}
