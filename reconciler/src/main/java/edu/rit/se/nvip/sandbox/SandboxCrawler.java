package edu.rit.se.nvip.sandbox;

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.rabbitmq.client.Channel;
import com.rabbitmq.client.Connection;
import com.rabbitmq.client.ConnectionFactory;
import edu.rit.se.nvip.model.RawVulnerability;
import edu.rit.se.nvip.utils.ReconcilerEnvVars;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeoutException;


public class SandboxCrawler {

    private static final DatabaseSandbox dbh = DatabaseSandbox.getInstance();
    private static final String QUEUE_NAME = "CRAWLER_OUT";

    public static void main() {
        ReconcilerEnvVars.loadFromFile();
        SandboxCrawler sand = new SandboxCrawler();
        String path = System.getProperty("user.dir") + "\\src\\main\\resources\\mock_crawler_output.json";
        List<RawVulnerability> vulns = sand.readJson(path);
        List<String> ids = new ArrayList<>();
        for(RawVulnerability vuln : vulns){
            dbh.insertRawVuln(vuln);
            ids.add(vuln.getCveId());
        }
        String jsonString = sand.genJson(ids);

        //send rabbit message to sandbox messenger
        try{
            // Create a connection factory and configure it
            ConnectionFactory factory = new ConnectionFactory();
            factory.setHost("localhost");
            factory.setUsername("guest");
            factory.setPassword("guest");

            // Create a connection to the RabbitMQ server
            Connection connection = factory.newConnection();

            // Create a channel
            Channel channel = connection.createChannel();

            // Declare the queue
            channel.queueDeclare(QUEUE_NAME, false, false, false, null);
            // Publish the message to the queue
            channel.basicPublish("", QUEUE_NAME, null, jsonString.getBytes());

            // Close the channel and connection
            channel.close();
            connection.close();
        } catch (IOException | TimeoutException e) {
            throw new RuntimeException(e);
        }



    }
    private String genJson(List<String> ids) {
        Gson gson = new Gson();
        return gson.toJson(ids);
    }

    public List<RawVulnerability> readJson(String jsonFile) {

        List<RawVulnerability> vulnList = new ArrayList<>();
        try (BufferedReader reader = new BufferedReader(new FileReader(jsonFile))) {
            StringBuilder jsonContent = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                jsonContent.append(line);
            }

            JsonObject jsonObject = JsonParser.parseString(jsonContent.toString()).getAsJsonObject();

            for (String key : jsonObject.keySet()) {
                JsonElement jsonElement = jsonObject.get(key);

                if (jsonElement.isJsonArray()) {
                    // Process the array of objects associated with the key
                    for (JsonElement element : jsonElement.getAsJsonArray()) {
                        JsonObject innerObject = element.getAsJsonObject();

                        // Extract values from the JSON object
                        String sourceURL = innerObject.get("sourceURL").getAsString();
                        String sourceType = innerObject.get("sourceType").getAsString();
                        int vulnID = innerObject.get("vulnID").getAsInt();
                        String cveId = innerObject.get("cveId").getAsString();
                        String description = innerObject.get("description").getAsString();
                        String publishedDate = innerObject.get("publishDate").getAsString();
                        String createdDate = innerObject.get("createDate").getAsString();
                        String lastModifiedDate = innerObject.get("lastModifiedDate").getAsString();

                        // Create RawVulnerability object
                        RawVulnerability rawVuln = new RawVulnerability(vulnID, cveId, description, Timestamp.valueOf(publishedDate), Timestamp.valueOf(lastModifiedDate), Timestamp.valueOf(createdDate), sourceURL, sourceType, 1);


                        vulnList.add(rawVuln);


                    }
                }
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        return vulnList;
    }

}