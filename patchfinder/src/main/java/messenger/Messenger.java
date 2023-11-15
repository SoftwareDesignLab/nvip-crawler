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
import com.rabbitmq.client.*;
import db.DatabaseHelper;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import patches.PatchFinder;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.sql.ResultSet;
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
    private final ConnectionFactory factory;
    private Connection inputConnection = null;
    private Channel inputChannel = null;
//    private static final Pattern CVE_REGEX = Pattern.compile("CVE-\\d{4}-\\d{4,7}");

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

//        try {
//            factory.useSslProtocol();
//        } catch (NoSuchAlgorithmException e) {
//            throw new RuntimeException(e);
//        } catch (KeyManagementException e) {
//            throw new RuntimeException(e);
//        }

        this.inputQueue = inputQueue;
    }

    // For JUnit tests
    protected Messenger(ConnectionFactory factory, String inputQueue) {
        logger.info("Initializing Messenger...");
        this.factory = factory;

//        try {
//            factory.useSslProtocol();
//        } catch (NoSuchAlgorithmException e) {
//            throw new RuntimeException(e);
//        } catch (KeyManagementException e) {
//            throw new RuntimeException(e);
//        }

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
            this.inputChannel.basicConsume(inputQueue, false, new DefaultConsumer(inputChannel) {
                @Override
                public void handleDelivery(String consumerTag, Envelope envelope, AMQP.BasicProperties properties, byte[] body) throws IOException {
                    String message = new String(body, StandardCharsets.UTF_8);
                    String cveId = parseMessage(message);

                    if(cveId != null) {
                        try { PatchFinder.run(cveId); }
                        catch (IOException e) {
                            throw new RuntimeException(e);
                        }
                    }
                    else logger.warn("Could not parse cveId from message '{}'", message);
                    inputChannel.basicAck(envelope.getDeliveryTag(), false);
                }
            });
        }
        catch (IOException | TimeoutException e) {
            throw new IllegalArgumentException("Rabbit connection could not be established");
        }
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
//        final Set<String> cveIds = dbh.getAffectedProducts(null).keySet();
        final Set<String> cveIds = new HashSet<>();
        try {
            ResultSet results = dbh.getConnection().prepareStatement("""
                    SELECT
                        v.cve_id
                    FROM
                        vulnerability v
                    JOIN
                        description d ON v.description_id = d.description_id
                    JOIN
                        affectedproduct ap ON v.cve_id = ap.cve_id
                    WHERE
                        ap.cpe LIKE '%tensorflow%'
                    GROUP BY
                        v.cve_id;
                    """).executeQuery();
            while(results != null && results.next()) cveIds.add(results.getString(1));
        } catch (Exception ignored) { }

        for (String id : cveIds) {
            id = "{\"cveId\": \"" + id + "\"}";
            m.sendDummyMessage(INPUT_QUEUE, id);
        }
    }
}
