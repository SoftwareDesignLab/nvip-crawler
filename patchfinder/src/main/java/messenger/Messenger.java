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
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import patches.PatchFinder;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.concurrent.*;
import java.util.regex.Pattern;

/**
 * Messenger class that handles RabbitMQ interaction
 *
 * @author Dylan Mulligan
 */
public class Messenger {
    private final String inputQueue;
    private static final Logger logger = LogManager.getLogger(DatabaseHelper.class.getSimpleName());
    private static final ObjectMapper OM = new ObjectMapper();
    private static final Pattern CVE_REGEX = Pattern.compile("CVE-\\d{4}-\\d{4,7}");
    private final ConnectionFactory factory;
    private Connection inputConnection = null;
    private Channel inputChannel = null;

    private final BlockingQueue<List<String>> jobListQueue = new LinkedBlockingQueue<>();

    // TODO: Only pull messages as we do jobs, leaving the rest of the queue intact
    // Define callback handler
    private static final DeliverCallback deliverCallback = (consumerTag, delivery) -> {
        String message = new String(delivery.getBody(), StandardCharsets.UTF_8);
        String cveId = parseMessage(message);
//        if(cveId != null) new Thread(() -> {
//            try {
//                PatchFinder.run(cveId);
//            } catch (IOException e) {
//                throw new RuntimeException(e);
//            }
//        }).start();

        if(cveId != null) {
            try {
                PatchFinder.run(cveId);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
        else logger.warn("Could not parse cveId from message '{}'", message);
//        List<String> parsedIds = parseIds(message);
//        if(parsedIds.size() > 0 && !jobListQueue.offer(parsedIds)) logger.error("Job response could not be added to message queue");
    };

    /**
     * Initialize the Messenger class with RabbitMQ host, username, and password
     * @param host RabbitMQ host
     * @param username RabbitMQ username
     * @param password RabbitMQ password
     */
    public Messenger(String host, String vhost, int port, String username, String password, String inputQueue) {
        logger.info("Initializing Messenger...");
        this.factory = new ConnectionFactory();
        this.factory.setHost(host);
        this.factory.setVirtualHost(vhost);
        this.factory.setPort(port);
        this.factory.setUsername(username);
        this.factory.setPassword(password);

        try {
            factory.useSslProtocol();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (KeyManagementException e) {
            throw new RuntimeException(e);
        }

        this.inputQueue = inputQueue;
    }

    // For JUnit tests
    protected Messenger(ConnectionFactory factory, String inputQueue) {
        logger.info("Initializing Messenger...");
        this.factory = factory;

        try {
            factory.useSslProtocol();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (KeyManagementException e) {
            throw new RuntimeException(e);
        }

        this.inputQueue = inputQueue;
    }

    private static Channel createChannel(Connection connection) {
        try { return connection.createChannel(); }
        catch (IOException e) { return null; }
    }

    private Channel getInputChannel() {
        // Get channel if still open, otherwise create new channel from connection object
        return this.inputChannel.isOpen() ? this.inputChannel : createChannel(this.inputConnection);
    }

    public void startHandlingJobs() {
        // Connect to rabbit input queue and subscribe callback
        try {
            this.inputConnection = this.factory.newConnection();
            this.inputChannel = this.inputConnection.createChannel();
            this.inputChannel.basicConsume(inputQueue, true, deliverCallback, consumerTag -> { });
        }
        catch (IOException | TimeoutException e) {
            throw new IllegalArgumentException("Rabbit connection could not be established");
        }
    }

    /**
     * Waits for a message from the PNE for pollInterval seconds, returning null unless a valid job was received
     *
     * @param pollInterval interval time in seconds to poll the blocking queue
     * @return null or a list of received CVE ids to find patches for
     */
    public List<String> waitForProductNameExtractorMessage(int pollInterval) {
        // Initialize job list
        List<String> cveIds = new ArrayList<>();

        final Channel inputChannel = this.getInputChannel();
        if(inputChannel != null) {

        }

        try(Channel channel = this.inputConnection.createChannel()) {
            // Declare the input queue
            channel.queueDeclare(inputQueue, true, false, false, null);
            channel.basicConsume(inputQueue, true, deliverCallback, consumerTag -> { });

            // Busy-wait loop for jobs
            while(cveIds.size() == 0) {
                // Poll queue for jobs every poll interval
                logger.info("Polling message queue...");

                // Create jobs list of lists for draining queue
                final List<List<String>> jobs = new ArrayList<>();
                // Drain queue to jobs list
                final int numReceivedJobs = jobListQueue.drainTo(jobs);
                // Flatten jobs into id list
                jobs.forEach(cveIds::addAll);

                // Sleep if no jobs received
                if(numReceivedJobs == 0)
                    synchronized (this) { wait(pollInterval * 1000L); }
            }
            logger.info("Received job with CVE(s) {}", cveIds);
        } catch (TimeoutException | InterruptedException | IOException e) {
            logger.error("Error occurred while getting jobs from the ProductNameExtractor: {}", e.toString());
        }

        return cveIds;
    }

    /**
     * Parse an id from a given json string. (String should be {'cveId': 'CVE-2023-1001'})
     * @param jsonString a JSON representation of an array of String CVE ids
     * @return parsed list of ids
     */
    public static String parseMessage(String jsonString) {
        try {
            logger.info("incoming cve list: {}", jsonString);
            final JsonNode messageNode = OM.readTree(jsonString);
            return messageNode.get("cveId").asText();
        } catch (JsonProcessingException e) {
            logger.error("Failed to parse list of ids from json string: {}", e.toString());
            return null;
        }
    }

    /**
     * Testing method for sending RabbitMQ messages
     * @param queue target queue
     * @param message message to be sent
     */
    private void sendDummyMessage(String queue, String message) {
        try(Connection connection = factory.newConnection();
            Channel channel = connection.createChannel()){

            channel.basicPublish("", queue, null, message.getBytes(StandardCharsets.UTF_8));

        } catch (IOException | TimeoutException e) {
            logger.error("Failed to send dummy message: {}", e.toString());
        }
    }

    public static void main(String[] args) {
        final String INPUT_QUEUE = "PNE_OUT";
        final Messenger m = new Messenger("localhost", "/", 5672 , "guest", "guest", INPUT_QUEUE);
        DatabaseHelper dbh = new DatabaseHelper("mysql", "jdbc:mysql://localhost:3306/nvip?useSSL=false&allowPublicKeyRetrieval=true", "root", "root");
        final Set<String> cveIds = dbh.getAffectedProducts(null).keySet();
        for (String id : cveIds) {
            m.sendDummyMessage(INPUT_QUEUE, id);
        }
//        m.sendDummyMessage(INPUT_QUEUE, "\"CVE-2023-0002\"");
//        m.sendDummyMessage(INPUT_QUEUE, "\"CVE-2023-0003\"");
//        m.sendDummyMessage(INPUT_QUEUE, "\"CVE-2023-0004\"");
//        m.sendDummyMessage(INPUT_QUEUE, "\"CVE-2023-0005\"");
//        m.sendDummyMessage(INPUT_QUEUE, "\"CVE-2023-0006\"");
//
//        try { Thread.sleep(5000); } catch (Exception ignored) { }
//
//        m.sendDummyMessage(INPUT_QUEUE, "\"CVE-2023-007\"");
//        m.sendDummyMessage(INPUT_QUEUE, "\"CVE-2023-008\"");
//        m.sendDummyMessage(INPUT_QUEUE, "\"CVE-2023-009\"");

//        m.waitForProductNameExtractorMessage(5);
//        ObjectMapper OM = new ObjectMapper();
//        try {
//            OM.writerWithDefaultPrettyPrinter().writeValue(new File("patchfinder/target/test.json"), "test1");
//            OM.writerWithDefaultPrettyPrinter().writeValue(new File("patchfinder/target/test.json"), "test2");
////            OM.writeValue(new File("patchfinder/target/test.json"), "test1");
////            OM.writeValue(new File("patchfinder/target/test.json"), "test2");
//            Thread.sleep(10000);
//        } catch (Exception e) {
//            e.printStackTrace();
//        }
    }
}
