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
import com.fasterxml.jackson.databind.ObjectMapper;
import com.rabbitmq.client.Channel;
import com.rabbitmq.client.Connection;
import com.rabbitmq.client.ConnectionFactory;
import com.rabbitmq.client.DeliverCallback;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import env.ProductNameExtractorEnvVars;

import java.io.*;
import java.nio.charset.StandardCharsets;
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
    private final static String INPUT_QUEUE = "RECONCILER_OUT";
    private final static String OUTPUT_QUEUE = "PNE_OUT";
    private static final Logger logger = LogManager.getLogger(Messenger.class.getSimpleName());
    private static final ObjectMapper OM = new ObjectMapper();
    private ConnectionFactory factory;

    public Messenger(){
        // Instantiate with default values
        this(
                ProductNameExtractorEnvVars.getRabbitHost(),
                ProductNameExtractorEnvVars.getRabbitUsername(),
                ProductNameExtractorEnvVars.getRabbitPassword()
        );
    }

    /**
     * Instantiate new RabbitMQ Messenger
     * @param host hostname
     * @param username username
     * @param password password
     */
    public Messenger(String host, String username, String password){
        factory = new ConnectionFactory();
        factory.setHost(host);
        factory.setUsername(username);
        factory.setPassword(password);
    }

    /**
     * Manually sets the factory
     *
     * @param factory ConnectionFactory to be set
     */
    public void setFactory(ConnectionFactory factory){
        this.factory = factory;
    }

    /**
     * Function to wait for jobs from the Reconciler, which upon reception will be passed to main to be processed.
     * Will continuously poll every pollInterval number of seconds until a message is received. Also handles
     * 'FINISHED' and 'TERMINATE' cases.
     *
     * @param pollInterval number of seconds between each poll to the queue
     * @return list of jobs or one-element list containing 'FINISHED' or 'TERMINATE'
     */
    public List<String> waitForReconcilerMessage(int pollInterval) {
        // Initialize job list
        List<String> cveIds = null;
        logger.info("Waiting for jobs from Reconciler...");
        final long startTime = System.currentTimeMillis();

        // Busy-wait loop for jobs
        while(cveIds == null) {
            try(Connection connection = factory.newConnection();
                Channel channel = connection.createChannel()){

                channel.queueDeclare(INPUT_QUEUE, false, false, false, null);

                BlockingQueue<List<String>> messageQueue = new ArrayBlockingQueue<>(1);

                DeliverCallback deliverCallback = (consumerTag, delivery) -> {
                    String message = new String(delivery.getBody(), StandardCharsets.UTF_8);

                    // If FINISHED or TERMINATE sent, just offer a 1 element list with the message
                    if(message.equals("FINISHED") || message.equals("TERMINATE")) {
                        List<String> noJobs = new ArrayList<>();
                        noJobs.add(message);
                        messageQueue.offer(noJobs);

                    // Otherwise jobs were sent, parseIds and then offer the list of jobs
                    } else {
                        List<String> parsedIds = parseIds(message);
                        if(parsedIds.size() > 0 && !messageQueue.offer(parsedIds)) logger.error("Job response could not be added to message queue");
                    }

                };

                channel.basicConsume(INPUT_QUEUE, true, deliverCallback, consumerTag -> { });

                logger.info("Polling message queue...");
                cveIds = messageQueue.poll(pollInterval, TimeUnit.SECONDS);
                final long elapsedTime = System.currentTimeMillis() - startTime;

                // Status log every 10 minutes
                if(elapsedTime / 1000 % 600 == 0){
                    logger.info("Messenger has been waiting for a message for {} minute(s)", elapsedTime / 1000 / 60);
                }

            } catch (TimeoutException | InterruptedException | IOException e) {
                logger.error("Error occurred while getting jobs from the ProductNameExtractor: {}", e.toString());
                break;
            }
        }

        return cveIds;
    }

    /**
     * Sends a list of jobs in the form of CVE IDs to be processed by the PatchFinder to the 'PNE_OUT' queue.
     *
     * @param cveIds list of jobs to be processed
     */
    public void sendPatchFinderMessage(List<String> cveIds) {

        try (Connection connection = factory.newConnection();
             Channel channel = connection.createChannel()) {
            channel.queueDeclare(OUTPUT_QUEUE, false, false, false, null);
            String message = genJson(cveIds);
            channel.basicPublish("", OUTPUT_QUEUE, null, message.getBytes(StandardCharsets.UTF_8));

        } catch (TimeoutException | IOException e) {
            logger.error("Error occurred while sending the PNE message to RabbitMQ: {}", e.getMessage());
        }
    }

    /**
     * Sends 'FINISHED' to the PatchFinder to notify it that all jobs have been processed within the PNE
     * and to not expect to receive any more jobs for the time being.
     */
    public void sendPatchFinderFinishMessage() {
        try (Connection connection = factory.newConnection();
             Channel channel = connection.createChannel()) {
            channel.queueDeclare(OUTPUT_QUEUE, false, false, false, null);
            String message = "FINISHED";
            channel.basicPublish("", OUTPUT_QUEUE, null, message.getBytes(StandardCharsets.UTF_8));

        } catch (TimeoutException | IOException e) {
            logger.error("Error occurred while sending the PNE message to RabbitMQ: {}", e.getMessage());
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
            return OM.readValue(jsonString, ArrayList.class);
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

    public static void main(String[] args) {
        Messenger messenger = new Messenger();
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
