package edu.rit.se.nvip.cwe;

import edu.rit.se.nvip.characterizer.CveCharacterizer;
import edu.rit.se.nvip.model.CompositeVulnerability;
import edu.rit.se.nvip.model.RawVulnerability;
import edu.rit.se.nvip.openai.OpenAIRequestHandler;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.*;
import java.net.URL;
import java.net.URLConnection;
import java.sql.Timestamp;
import java.util.HashSet;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

public class CweController {

    private static final String URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip";
    private static final String PATH = System.getProperty("user.dir") + "\\src\\main\\resources\\cwedata\\cwec_v4.12.xml";
    private Logger logger = LogManager.getLogger(CveCharacterizer.class.getSimpleName());

    public static void main(String[] args) {
        CweController cwe = new CweController();
        cwe.getCWEsFromWeb();
        Set<CWE> CWEs = cwe.readFile(PATH);

        ChatGPTProcessor gpt = new ChatGPTProcessor();
        RawVulnerability rawVuln = new RawVulnerability(1, "cve-1",
                "mailcow is a mail server suite based on Dovecot, Postfix and other open source software, that provides a modern web UI for user/server administration. " +
                        "A vulnerability has been discovered in mailcow which allows an attacker to manipulate internal Dovecot variables by using specially crafted passwords during " +
                        "the authentication process. The issue arises from the behavior of the `passwd-verify.lua` script, which is responsible for verifying user passwords during login " +
                        "attempts. Upon a successful login, the script returns a response in the format of \"password=<valid-password>\", indicating the successful authentication. " +
                        "By crafting a password with additional key-value pairs appended to it, an attacker can manipulate the returned string and influence the internal behavior of Dovecot. " +
                        "For example, using the password \"123 mail_crypt_save_version=0\" would cause the `passwd-verify.lua` script to return the string \"password=123 " +
                        "mail_crypt_save_version=0\". Consequently, Dovecot will interpret this string and set the internal variables accordingly, leading to unintended consequences. " +
                        "This vulnerability can be exploited by an authenticated attacker who has the ability to set their own password. Successful exploitation of this vulnerability " +
                        "could result in unauthorized access to user accounts, bypassing security controls, or other malicious activities. " +
                        "This issue has been patched in version `2023-05a`. Users are advised to upgrade. There are no known workarounds for this vulnerability. ",
                new Timestamp(System.currentTimeMillis()),
                new Timestamp(System.currentTimeMillis()),
                new Timestamp(System.currentTimeMillis()),
                "www.example.com");
        CompositeVulnerability vuln = new CompositeVulnerability(rawVuln);
        gpt.assignCWEs(vuln);
        OpenAIRequestHandler.getInstance().shutdown();

    }

    public void getCWEsFromWeb() {
        String saveDir = System.getProperty("user.dir") + "\\src\\main\\resources\\cwedata\\";

        try {
            downloadFile(URL, saveDir);
            logger.info("File downloaded successfully.");
        } catch (IOException e) {
            logger.error("Error occurred while downloading the file: " + e.getMessage());
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

        // Unzip the downloaded file
        File zipFile = new File(saveDir + "cwec_latest.xml.zip");
        File outputFolder = new File(saveDir);
        unzipFile(zipFile, outputFolder);
    }

    private static void unzipFile(File zipFile, File outputFolder) throws IOException {
        byte[] buffer = new byte[4096];
        ZipInputStream zipInputStream = new ZipInputStream(new FileInputStream(zipFile));
        ZipEntry entry = zipInputStream.getNextEntry();

        while (entry != null) {
            String entryName = entry.getName();
            File entryFile = new File(outputFolder, entryName);

            // Create directories if the entry is a folder
            if (entry.isDirectory()) {
                entryFile.mkdirs();
            } else {
                // Create parent directories for the file
                entryFile.getParentFile().mkdirs();

                // Extract the file
                FileOutputStream outputStream = new FileOutputStream(entryFile);
                int bytesRead;
                while ((bytesRead = zipInputStream.read(buffer)) != -1) {
                    outputStream.write(buffer, 0, bytesRead);
                }
                outputStream.close();
            }

            // Move to the next entry
            zipInputStream.closeEntry();
            entry = zipInputStream.getNextEntry();
        }

        // Close the zip input stream
        zipInputStream.close();
    }

    private Set<CWE> readFile(String filePath) {
        Set<CWE> cweList = new HashSet<>();
        try {
            // Load the XML file
            File xmlFile = new File(filePath);
            DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
            DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
            Document doc = dBuilder.parse(xmlFile);

            // Normalize the document
            doc.getDocumentElement().normalize();

            // Get the root element
            Element root = doc.getDocumentElement();

            // Access elements and attributes
            NodeList weaknessNodes = root.getElementsByTagName("Weakness");
            for (int i = 0; i < weaknessNodes.getLength(); i++) {
                Element weaknessElement = (Element) weaknessNodes.item(i);
                int id = Integer.parseInt(weaknessElement.getAttribute("ID"));
                String name = weaknessElement.getAttribute("Name");
                String extendedDesc = "";

                // Extract Extended_Description content
                NodeList extendedDescNodes = weaknessElement.getElementsByTagName("Extended_Description");
                if (extendedDescNodes.getLength() > 0) {
                    Element extendedDescElement = (Element) extendedDescNodes.item(0);
                    extendedDesc = extendedDescElement.getTextContent();
                }

                // Create CWE object and add it to the list
                if (!name.contains("DEPRECATED:")) {
                    CWE cwe = new CWE(id, name, extendedDesc);

                    // Process children
                    NodeList relatedWeaknessNodes = weaknessElement.getElementsByTagName("Related_Weakness");
                    for (int j = 0; j < relatedWeaknessNodes.getLength(); j++) {
                        Element relatedWeaknessElement = (Element) relatedWeaknessNodes.item(j);
                        String nature = relatedWeaknessElement.getAttribute("Nature");
                        if (nature.equals("ChildOf")) {
                            int parentId = Integer.parseInt(relatedWeaknessElement.getAttribute("CWE_ID"));
                            cwe.addParentId(parentId);
                        }
                    }

                    cweList.add(cwe);
                }
            }
            for (CWE cwe : cweList){
                cwe.generateFamily(cweList);
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
        return cweList;
    }
}