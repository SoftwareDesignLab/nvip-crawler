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
import db.DatabaseHelper;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.*;

/**
 * Messenger class that handles RabbitMQ interaction
 *
 * @author Dylan Mulligan
 */
public class Messenger {
    private final static String INPUT_QUEUE = "PNE_OUT";
    private static final Logger logger = LogManager.getLogger(DatabaseHelper.class.getSimpleName());
    private static final ObjectMapper OM = new ObjectMapper();
    private ConnectionFactory factory;

    /**
     * Initialize the Messenger class with RabbitMQ host, username, and password
     * @param host RabbitMQ host
     * @param username RabbitMQ username
     * @param password RabbitMQ password
     */
    public Messenger(String host, String username, String password) {
        this.factory = new ConnectionFactory();
        factory.setHost(host);
        factory.setUsername(username);
        factory.setPassword(password);
    }

    public void setFactory(ConnectionFactory factory) {
        this.factory = factory;
    }

    /**
     * Waits for a message from the PNE for pollInterval seconds, returning null unless a valid job was received
     *
     * @param pollInterval time to wait before timing out and returning null
     * @return null or a list of received CVE ids to find patches for
     */
    public List<String> waitForProductNameExtractorMessage(int pollInterval) {
        // Initialize job list
        List<String> cveIds = null;

        // Busy-wait loop for jobs
        while(cveIds == null) {
            try(Connection connection = factory.newConnection();
                Channel channel = connection.createChannel()){

                channel.queueDeclare(INPUT_QUEUE, false, false, false, null);

                BlockingQueue<List<String>> messageQueue = new ArrayBlockingQueue<>(1);

                DeliverCallback deliverCallback = (consumerTag, delivery) -> {
                    String message = new String(delivery.getBody(), StandardCharsets.UTF_8);
                    List<String> parsedIds = parseIds(message);
                    if(parsedIds.size() > 0 && !messageQueue.offer(parsedIds)) logger.error("Job response could not be added to message queue");
                };
                channel.basicConsume(INPUT_QUEUE, true, deliverCallback, consumerTag -> { });

                logger.info("Polling message queue...");
                cveIds = messageQueue.poll(pollInterval, TimeUnit.SECONDS);
                if(cveIds != null) logger.info("Received job with CVE(s) {}", cveIds);

            } catch (TimeoutException | InterruptedException | IOException e) {
                logger.error("Error occurred while getting jobs from the ProductNameExtractor: {}", e.toString());
                break;
            }
        }


        return cveIds;
    }

    /**
     * Parse a list of ids from a given json string. (String should be )
     * @param jsonString a JSON representation of an array of String CVE ids
     * @return parsed list of ids
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
     * Testing method for sending RabbitMQ messages
     * @param queue target queue
     * @param message message to be sent
     */
    private void sendDummyMessage(String queue, String message) {
        try(Connection connection = factory.newConnection();
            Channel channel = connection.createChannel()){

            channel.queueDeclare(queue, false, false, false, null);

            channel.basicPublish("", queue, null, message.getBytes());

        } catch (IOException | TimeoutException e) {
            logger.error("Failed to send dummy message: {}", e.toString());
        }
    }

    public static void main(String[] args) {
//        final Messenger m = new Messenger("localhost", "guest", "guest");
//        m.sendDummyMessage(INPUT_QUEUE, "[\"CVE-2023-2933\", \"CVE-2023-2934\"]");
        ObjectMapper OM = new ObjectMapper();
        try {
            OM.writerWithDefaultPrettyPrinter().writeValue(new File("patchfinder/target/test.json"), "test1");
            OM.writerWithDefaultPrettyPrinter().writeValue(new File("patchfinder/target/test.json"), "test2");
//            OM.writeValue(new File("patchfinder/target/test.json"), "test1");
//            OM.writeValue(new File("patchfinder/target/test.json"), "test2");
            Thread.sleep(10000);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
