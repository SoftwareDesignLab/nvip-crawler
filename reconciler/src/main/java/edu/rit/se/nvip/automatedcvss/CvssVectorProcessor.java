/**
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
*/

package edu.rit.se.nvip.automatedcvss;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import edu.rit.se.nvip.characterizer.CveCharacterizer;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.checkerframework.checker.units.qual.C;

import java.io.*;
import java.net.URL;
import java.net.URLConnection;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.time.Year;
import java.util.ArrayList;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

public class CvssVectorProcessor {
    private static Logger logger = LogManager.getLogger(CvssVectorProcessor.class.getSimpleName());
    private static final String saveDir = System.getProperty("user.dir") + "\\src\\main\\resources\\cvedata\\";
    private static final String cveDir = saveDir + "nvdcve-1.1-2023.json";
    private static String URL;

    private boolean useNVDandCVEDates = true;

    private boolean useCVEYear = false;

    public CvssVectorProcessor(int year){
        logger.info("Loading NVD Cves! Year: " + year);
        URL = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-" + year + ".json.zip";
    }
    public CvssVectorProcessor(){
        this(Integer.parseInt(Year.now().toString()));
    }
    public static void main(String[] args) {
        CvssVectorProcessor proc = new CvssVectorProcessor();
        JsonArray array = proc.getNvdJsonsFromWeb();
        proc.processCveItems(array);
    }
    public JsonArray getNvdJsonsFromWeb() {

        try {
            downloadFile(URL);
            logger.info("File downloaded successfully.");
            return getJsonFromFile();
        } catch (IOException e) {
            logger.error("Error occurred while downloading the file: " + e.getMessage());
            return null;
        }
    }

    private static void downloadFile(String fileURL) throws IOException {
        URL url = new URL(fileURL);
        URLConnection connection = url.openConnection();
        BufferedInputStream inputStream = new BufferedInputStream(connection.getInputStream());
        FileOutputStream outputStream = new FileOutputStream(saveDir + "nvd_latest.zip");

        byte[] buffer = new byte[4096];
        int bytesRead;
        while ((bytesRead = inputStream.read(buffer)) != -1) {
            outputStream.write(buffer, 0, bytesRead);
        }

        outputStream.close();
        inputStream.close();

        // Unzip the downloaded file
        File zipFile = new File(saveDir + "nvd_latest.zip");
        File outputFolder = new File(saveDir);
        unzipFile(zipFile, outputFolder);
        zipFile.delete();
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
    private JsonArray getJsonFromFile(){
        try {
            // Read the JSON data from the file using Gson
            JsonParser jsonParser = new JsonParser();
            JsonElement jsonElement = jsonParser.parse(new FileReader(cveDir));
            JsonObject jsonObject = jsonElement.getAsJsonObject();

            return jsonObject.getAsJsonArray("CVE_Items");

        } catch (Exception e) {
            logger.error("Error reading json file, make sure path is correct");
            return null;
        }
    }

    public void processCveItems(JsonArray cveItems) {
        List<JsonArray> vectors = new ArrayList<>();
        int yearChangeCountTotal = 0;

        for (JsonElement cveItemElement : cveItems) {
            JsonObject cveItem = cveItemElement.getAsJsonObject();

            String cveId = cveItem.getAsJsonObject("cve")
                    .getAsJsonObject("CVE_data_meta")
                    .get("ID").getAsString();

            JsonObject impact = cveItem.getAsJsonObject("impact");
            JsonObject baseMetricV3 = impact.has("baseMetricV3")
                    ? impact.getAsJsonObject("baseMetricV3")
                    .getAsJsonObject("cvssV3")
                    : null;

            if (baseMetricV3 != null) {
                String publishedDate = cveItem.get("publishedDate").getAsString();
                int cveYear = Integer.parseInt(cveId.split("-")[1]);
                int publishedYear = Integer.parseInt(publishedDate.split("-")[0]);
                boolean yearChange = false;
                if (useNVDandCVEDates) {
                    if (publishedYear > cveYear) {
                        publishedDate = cveYear + "-12-31";
                        yearChange = true;
                        yearChangeCountTotal++;
                    }
                } else if (useCVEYear) {
                    publishedDate = cveYear + "-12-31";
                }

                JsonArray problemType = cveItem.getAsJsonObject("cve")
                        .getAsJsonObject("problemtype")
                        .getAsJsonArray("problemtype_data");

                boolean cwEnoinfo = false;
                boolean cweOther = false;
                JsonArray cweList = new JsonArray();
                for (JsonElement data : problemType) {
                    for (JsonElement entry : data.getAsJsonObject().getAsJsonArray("description")) {
                        String value = entry.getAsJsonObject().get("value").getAsString();
                        if (value.equals("NVD-CWE-noinfo")) {
                            cwEnoinfo = true;
                        } else if (value.equals("NVD-CWE-Other")) {
                            cweOther = true;
                            cweList.add(0);
                        } else {
                            int cwe = Integer.parseInt(value.split("-")[1]);
                            cweList.add(cwe);
                        }
                    }
                }
                if (cweOther) {
                    cwEnoinfo = false;
                }

                JsonObject baseMetricV3Data = cveItem.getAsJsonObject("impact")
                        .getAsJsonObject("baseMetricV3");

                JsonArray vectorList = new JsonArray();
                vectorList.add(cveId);
                vectorList.add(publishedDate);
                vectorList.add(yearChange ? 1 : 0);
                vectorList.add(cweList);

                String vectorString = baseMetricV3.get("vectorString").getAsString();
                String[] vectorAttributes = vectorString.split("[/:]");
                double baseScore = baseMetricV3.get("baseScore").getAsDouble();
                double exploitabilityScore = baseMetricV3Data.get("exploitabilityScore").getAsDouble();
                double impactScore = baseMetricV3Data.get("impactScore").getAsDouble();

                vectorList.add(3); //CVSS version
                vectorList.add(baseScore);
                vectorList.add(exploitabilityScore);
                vectorList.add(impactScore);
                for (int i = 3; i < vectorAttributes.length; i = i + 2) { // Start from index 1 to skip the empty first element
                    vectorList.add(vectorAttributes[i]);
                }

                vectors.add(vectorList);
            }
        }

        System.out.println("\nFinal Statistics, " + cveItems.size() + " CVE count, "
                + yearChangeCountTotal + " yearChangeCountTotal");

        writeVectorsToCsv(vectors);
    }

    private void writeVectorsToCsv(List<JsonArray> vectors) {
        String csvFilePath = saveDir + "output.csv";

        // Delete existing file if it exists
        File existingFile = new File(csvFilePath);
        if (existingFile.exists()) {
            if (existingFile.delete()) {
                System.out.println("Existing CSV file deleted: " + csvFilePath);
            } else {
                System.err.println("Unable to delete existing CSV file: " + csvFilePath);
            }
        }

        try (FileWriter writer = new FileWriter(csvFilePath)) {
            // Write CSV header
            writer.write("CVE ID,Published Date,Year Change,CWE List,CVSS Version,Base Score,"
                    + "Exploitability Score,Impact Score,Attack Vector,Attack Complexity,Privileges Required,"
                    + "User Interaction,Scope,Confidentiality Impact,Integrity Impact,Availability Impact\n");

            // Write CVE vectors
            for (JsonArray vectorList : vectors) {
                StringBuilder line = new StringBuilder();
                for (JsonElement element : vectorList) {
                    if (element.isJsonPrimitive()) {
                        line.append("\"").append(element.getAsString()).append("\",");
                    } else {
                        // Handle complex types, e.g., arrays and objects
                        String serializedElement = element.toString();
                        line.append("\"").append(serializedElement).append("\",");
                    }
                }
                line.deleteCharAt(line.length() - 1); // Remove trailing comma
                writer.write(line.toString() + "\n");
            }

            System.out.println("CSV file created successfully: " + csvFilePath);
        } catch (IOException e) {
            System.err.println("Error writing to CSV file: " + e.getMessage());
        }
    }
}
