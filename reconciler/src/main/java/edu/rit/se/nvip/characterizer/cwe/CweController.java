/ **
* Copyright 2021 Rochester Institute of Technology (RIT). Developed with
* government support under contract 70RCSA22C00000008 awarded by the United
* States Department of Homeland Security for Cybersecurity and Infrastructure Security Agency.
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the “Software”), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in
* all copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE.
* /

package edu.rit.se.nvip.characterizer.cwe;

import edu.rit.se.nvip.characterizer.CveCharacterizer;
import edu.rit.se.nvip.reconciler.openai.OpenAIRequestHandler;
import edu.rit.se.nvip.db.model.CompositeVulnerability;
import edu.rit.se.nvip.db.model.RawVulnerability;
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
    private static Logger logger = LogManager.getLogger(CveCharacterizer.class.getSimpleName());

    public static void main(String[] args) {
        CweController cwe = new CweController();
        cwe.getCWEsFromWeb();
        Set<CWE> CWEs = cwe.readFile(PATH);

        ChatGPTProcessor gpt = new ChatGPTProcessor();
        RawVulnerability rawVuln = new RawVulnerability(1, "cve-1",
                "The ntpd_driver component before 1.3.0 and 2.x before 2.2.0 for Robot Operating System (ROS) allows attackers, " +
                        "who control the source code of a different node in the same ROS application, to change a robot's behavior. " +
                        "This occurs because a topic name depends on the attacker-controlled time_ref_topic parameter.",
                new Timestamp(System.currentTimeMillis()),
                new Timestamp(System.currentTimeMillis()),
                new Timestamp(System.currentTimeMillis()),
                "www.example.com");
        CompositeVulnerability vuln = new CompositeVulnerability(rawVuln);
        Set<CWE> gptCWEs = gpt.assignCWEs(vuln);
        OpenAIRequestHandler.getInstance().shutdown();
        for(CWE cw : gptCWEs){
            logger.info(cw.getId() + ": " + cw.getName());
        }
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