package messenger;

/**
 * Copyright 2023 Rochester Institute of Technology (RIT). Developed with
 * government support under contract 70RSAT19CB0000020 awarded by the United
 * States Department of Homeland Security.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.rabbitmq.client.Channel;
import com.rabbitmq.client.Connection;
import com.rabbitmq.client.ConnectionFactory;
import com.rabbitmq.client.DeliverCallback;
import db.DatabaseHelper;
import model.cpe.AffectedProduct;
import model.cve.CompositeVulnerability;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import env.ProductNameExtractorEnvVars;
import productdetection.AffectedProductIdentifier;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.concurrent.*;

/**
 * Messenger class used to handle RabbitMQ implementation in the Product Name Extractor.
 *
 * Includes functionality to receive jobs from the Reconciler and send jobs to the PatchFinder.
 *
 * @author Paul Vickers
 * @author Dylan Mulligan
 * @author Steven Shadders
 */
public class Messenger {
    private final String inputQueue;
    private final String outputQueue;
    private static final Logger logger = LogManager.getLogger(Messenger.class.getSimpleName());
    private static final ObjectMapper OM = new ObjectMapper();

    private ConnectionFactory factory;
    private AffectedProductIdentifier affectedProductIdentifier;
    private DatabaseHelper databaseHelper;


    public Messenger(ConnectionFactory connectionFactory, String inputQueue, String outputQueue, AffectedProductIdentifier affectedProductIdentifier, DatabaseHelper databaseHelper){
        this.factory = connectionFactory;
        this.inputQueue = inputQueue;
        this.outputQueue = outputQueue;
        this.affectedProductIdentifier = affectedProductIdentifier;
        this.databaseHelper = databaseHelper;
    }

    public void run() {
        try (Connection connection = factory.newConnection();
             Channel channel = connection.createChannel()) {

            channel.queueDeclare(inputQueue, false, false, false, null);
            channel.queueDeclare(outputQueue, false, false, false, null);

            DeliverCallback deliverCallback = (consumerTag, delivery) -> {
                String message = new String(delivery.getBody(), StandardCharsets.UTF_8);
                List<String> cveIds = parseIds(message);

                logger.info("Received job with CVE(s) {}", cveIds);

                // Pull specific cve information from database for each CVE ID passed from reconciler
                List<CompositeVulnerability> vulnList = databaseHelper.getSpecificCompositeVulnerabilities(cveIds);

                // Identify affected products from the CVEs
                final long getProdStart = System.currentTimeMillis();
                List<AffectedProduct> affectedProducts = affectedProductIdentifier.identifyAffectedProducts(vulnList);

                // Insert the affected products found into the database
                databaseHelper.insertAffectedProductsToDB(affectedProducts);
                logger.info("Product Name Extractor found and inserted {} affected products to the database in {} seconds", affectedProducts.size(), Math.floor(((double) (System.currentTimeMillis() - getProdStart) / 1000) * 100) / 100);

                // Clear cveIds, extract only the cveIds for which affected products were found to be sent to the Patchfinder
                cveIds.clear();
                for (AffectedProduct affectedProduct : affectedProducts) {
                    if (!cveIds.contains(affectedProduct.getCveId())) cveIds.add(affectedProduct.getCveId());
                }

                logger.info("Sending jobs to patchfinder...");
                String response = genJson(cveIds);
                channel.basicPublish("", outputQueue, null, response.getBytes(StandardCharsets.UTF_8));
                logger.info("Jobs have been sent!\n\n");
            };

            channel.basicConsume(inputQueue, true, deliverCallback, consumerTag -> {});

        } catch (IOException | TimeoutException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Takes a JSON string containing all CVE jobs to be processed and splits them into a list
     *
     * @param jsonString string containing the CVE IDs
     * @return list of CVE IDs
     */
    @SuppressWarnings("unchecked")
    public List<String> parseIds(String jsonString) {
        try {
            List<String> ids = new ArrayList<>();
            JsonNode node = OM.readTree(jsonString);
            if (node.has("cveId")){
                ids.add(node.get("cveId").asText());
            }
            return ids;
        } catch (JsonProcessingException e) {
            logger.error("Failed to parse list of ids from json string: {}", e.toString());
            return new ArrayList<>();
        }
    }

    /**
     * Takes in a list of CVE IDs and transforms it into a JSON string to be sent via RabbitMQ.
     *
     * @param cveIds list of CVE IDs
     * @return single JSON string of all CVE IDs
     */
    private String genJson(List<String> cveIds) {
        try {
            return OM.writeValueAsString(cveIds);
        } catch (JsonProcessingException e) {
            logger.error("Failed to convert list of ids to json string: {}", e.toString());
            return "";
        }
    }

    private void sendDummyMessage(String queue, List<String> cveIds) {
        try (Connection connection = factory.newConnection();
             Channel channel = connection.createChannel()) {
            channel.queueDeclare(queue, false, false, false, null);
            String message = genJson(cveIds);
            channel.basicPublish("", queue, null, message.getBytes(StandardCharsets.UTF_8));
            logger.info("Successfully sent message:\n\"{}\"", message);
        } catch (IOException | TimeoutException e) { logger.error("Error sending message: {}", e.toString()); }
    }

    private static List<String> getIdsFromFile(String filename) {
        try {
            // Return ids
            return OM.readerForListOf(String.class).readValue(new File(filename), ArrayList.class);
        }
        catch (IOException e) { logger.error("Failed to get ids from file '{}'", filename); }
        return new ArrayList<>();
    }

    private void sendDummyBatchedList(String queue, List<String> messages, int batchSize) {
        // 0 results in no batching
        if(batchSize == 0) batchSize = messages.size();

        // Get number of batches (including any partial batches)
        final int numBatches = (int) Math.ceil((double) messages.size() / batchSize);

        // Determine if there is a partial batch
        final boolean hasPartial = messages.size() % batchSize != 0;

        // Send batches
        for (int i = 0; i < numBatches; i++) {
            if(!hasPartial && i + 1 == numBatches) this.sendDummyMessage(queue, messages.subList(i * batchSize, messages.size() - 1));
            else this.sendDummyMessage(queue, messages.subList(i * batchSize, (i + 1) * batchSize));
        }
    }

    private static List<String> getIdsFromJson(String path) {
        try {
            final LinkedHashMap<String, ArrayList> data = OM.readValue(new File(path), LinkedHashMap.class);
            return new ArrayList<>(data.keySet());
        } catch (IOException e) {
            return new ArrayList<>();
        }
    }

    private static void writeIdsToFile(List<String> ids, String path) {
        try {
            FileWriter writer = new FileWriter(path);

            for (String id: ids) {
                writer.write(id + "\n");
            }
            writer.close();
        } catch (IOException e) {
            logger.error("Failed to write ids to file: {}", e.toString());
        }
    }

    /**
     * Manually sets the factory
     *
     * @param factory ConnectionFactory to be set
     */
    public void setFactory(ConnectionFactory factory){
        this.factory = factory;
    }

    public static void main(String[] args) {
        List<CompositeVulnerability> vulnList = new ArrayList<>();
        // Initialize the affectedProductIdentifier and get ready to process cveIds

        ConnectionFactory factory = new ConnectionFactory();
        factory.setHost(ProductNameExtractorEnvVars.getRabbitHost());
        factory.setVirtualHost(ProductNameExtractorEnvVars.getRabbitVHost());
        factory.setPort(ProductNameExtractorEnvVars.getRabbitPort());
        factory.setUsername(ProductNameExtractorEnvVars.getRabbitUsername());
        factory.setPassword(ProductNameExtractorEnvVars.getRabbitPassword());

        try {
            factory.useSslProtocol();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (KeyManagementException e) {
            throw new RuntimeException(e);
        }

//        Messenger messenger = new Messenger(
//                factory,
//                ProductNameExtractorEnvVars.getRabbitInputQueue(),
//                ProductNameExtractorEnvVars.getRabbitOutputQueue(),
//                affectedProductIdentifier,
//                databaseHelper);
        List<String> cveIds = new ArrayList<>();
        cveIds.addAll(getIdsFromJson("test_output.json"));
        writeIdsToFile(cveIds, "test_ids.txt");
//        messenger.sendDummyMessage("CRAWLER_OUT", cveIds);
//        cveIds.add("CVE-2008-2951");
//        cveIds.add("CVE-2014-0472");
//        cveIds.add("TERMINATE");
//        cveIds.addAll(getIdsFromFile("cves-short.csv"));
//        messenger.sendDummyList("RECONCILER_OUT", cveIds);
//        messenger.sendDummyBatchedList("PNE_OUT", cveIds, 100);

    }
}
