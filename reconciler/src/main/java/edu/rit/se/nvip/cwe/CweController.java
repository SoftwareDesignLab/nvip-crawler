package edu.rit.se.nvip.cwe;

import java.io.BufferedInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.URL;
import java.net.URLConnection;

public class CweController {

    /*
    STILL WORK IN PROGRESS, THIS SHOULD GET THE XML FILE WE NEED WITH THE CWEs
     */
    private static final String url = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip";

    public void getCWEsFromWeb() {
        String saveDir = "<Specify the directory to save the file>"; //instead of saving it we need to send a message to chatgpt

        try {
            downloadFile(url, saveDir);
            System.out.println("File downloaded successfully.");
        } catch (IOException e) {
            System.out.println("Error occurred while downloading the file: " + e.getMessage());
        }
    }

    private static void downloadFile(String fileURL, String saveDir) throws IOException {
        URL url = new URL(fileURL);
        URLConnection connection = url.openConnection();
        BufferedInputStream inputStream = new BufferedInputStream(connection.getInputStream());
        FileOutputStream outputStream = new FileOutputStream(saveDir + "cwec_latest.xml.zip");

        byte[] buffer = new byte[4096];
        int bytesRead;
        while ((bytesRead = inputStream.read(buffer)) != -1) {
            outputStream.write(buffer, 0, bytesRead);
        }

        outputStream.close();
        inputStream.close();
    }
}