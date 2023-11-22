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
import fixes.FixFinder;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import patches.PatchFinder;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.concurrent.*;

/**
 * Messenger class that handles RabbitMQ interaction
 *
 * @author Dylan Mulligan
 */
public class Messenger {
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
    public Messenger(String host, String vhost, int port, String username, String password) {
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
    }

    // For JUnit tests
    protected Messenger(ConnectionFactory factory) {
        logger.info("Initializing Messenger...");
        this.factory = factory;

        try {
            factory.useSslProtocol();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (KeyManagementException e) {
            throw new RuntimeException(e);
        }
    }

    public void startHandlingPatchJobs(String inputQueue) {
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

    public void startHandlingFixJobs(String inputQueue) {
        // Connect to rabbit input queue and subscribe callback
        try {
            this.inputConnection = this.factory.newConnection();
            this.inputChannel = this.inputConnection.createChannel();
            this.inputChannel.basicConsume(inputQueue, false, new DefaultConsumer(inputChannel) {
                @Override
                public void handleDelivery(String consumerTag, Envelope envelope, AMQP.BasicProperties properties, byte[] body) throws IOException {
                    String message = new String(body, StandardCharsets.UTF_8);
                    String cveId = parseMessage(message);

                    if(cveId != null) FixFinder.run(cveId);
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
            logger.info("Incoming CVE: '{}'", jsonString);
            final JsonNode messageNode = OM.readTree(jsonString);
            return messageNode.get("cveId").asText();
        } catch (JsonProcessingException e) {
            logger.error("Failed to parse id from json string: {}", e.toString());
            return null;
        }
    }

    /**
     * Testing method for sending RabbitMQ messages
     * @param message message to be sent
     */
    private void sendDummyMessage(String message, String inputQueue) {
        try(Connection connection = factory.newConnection();
            Channel channel = connection.createChannel()){

            channel.basicPublish("", inputQueue, null, message.getBytes(StandardCharsets.UTF_8));

        } catch (IOException | TimeoutException e) {
            logger.error("Failed to send dummy message: {}", e.toString());
        }
    }

    public static void main(String[] args) {
        final String PF_INPUT_QUEUE = "PNE_OUT_FIX";
        final String FF_INPUT_QUEUE = "PNE_OUT_PATCH";
        final Messenger m = new Messenger("localhost", "/", 5672 , "guest", "guest");
        DatabaseHelper dbh = new DatabaseHelper("mysql", "jdbc:mysql://localhost:3306/nvip?useSSL=false&allowPublicKeyRetrieval=true", "root", "root");
        final Set<String> cveIds = dbh.getAffectedProducts(null).keySet();
//        final Set<String> cveIds = new HashSet<>();
//        try {
//            ResultSet results = dbh.getConnection().prepareStatement("""
//                    SELECT
//                        v.cve_id
//                    FROM
//                        vulnerability v
//                    JOIN
//                        description d ON v.description_id = d.description_id
//                    JOIN
//                        affectedproduct ap ON v.cve_id = ap.cve_id
//                    WHERE
//                        ap.cpe LIKE '%tensorflow%'
//                    GROUP BY
//                        v.cve_id;
//                    """).executeQuery();
//            while(results != null && results.next()) cveIds.add(results.getString(1));
//        } catch (Exception ignored) { }

        for (String id : cveIds) {
            id = "{\"cveId\": \"" + id + "\"}";
            m.sendDummyMessage(id, PF_INPUT_QUEUE);
            m.sendDummyMessage(id, FF_INPUT_QUEUE);
        }
    }
}
