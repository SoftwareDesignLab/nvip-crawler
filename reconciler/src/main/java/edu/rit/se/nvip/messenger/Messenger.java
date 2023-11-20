package edu.rit.se.nvip.messenger;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.rabbitmq.client.Channel;
import com.rabbitmq.client.Connection;
import com.rabbitmq.client.ConnectionFactory;
import com.rabbitmq.client.DeliverCallback;
import edu.rit.se.nvip.utils.ReconcilerEnvVars;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

public class Messenger {

    private final String inputQueue;
    private final String outputQueue;
    private static final Logger logger = LogManager.getLogger(Messenger.class.getSimpleName());
    private static final ObjectMapper OM = new ObjectMapper();
    private ConnectionFactory factory;

    public Messenger(){
        // Instantiate with default values
        this(
                ReconcilerEnvVars.getRabbitHost(),
                ReconcilerEnvVars.getRabbitVHost(),
                ReconcilerEnvVars.getRabbitPort(),
                ReconcilerEnvVars.getRabbitUsername(),
                ReconcilerEnvVars.getRabbitPassword(),
                ReconcilerEnvVars.getRabbitQueueIn(),
                ReconcilerEnvVars.getRabbitQueueOut());
    }

    /**
     * Instantiate new RabbitMQ Messenger
     * @param host hostname
     * @param username username
     * @param password password
     */
    public Messenger(String host, String vhost, int port, String username, String password, String inputQueue, String outputQueue){
        logger.info("Creating RabbitMQ Connection to following url: {}:{}/{}", host, port, vhost);
        factory = new ConnectionFactory();
        factory.setHost(host);
        factory.setVirtualHost(vhost);
        factory.setPort(port);
        factory.setUsername(username);
        factory.setPassword(password);

        try {
            factory.useSslProtocol();
        } catch (NoSuchAlgorithmException e) {
            logger.error(e.getMessage());
            throw new RuntimeException(e);
        } catch (KeyManagementException e) {
            logger.error(e.getMessage());
            throw new RuntimeException(e);
        }

        this.inputQueue = inputQueue;
        this.outputQueue = outputQueue;
    }

    /**
     * Used in tests to set a mock factory
     * @param factory
     */
    public void setFactory(ConnectionFactory factory) {
        this.factory = factory;
    }

    /**
     * Waits for message to be sent from Crawler for rabbitTimeout amount of seconds and retrieves it
     * @param rabbitTimeout
     * @return
     * @throws Exception
     */
    public List<String> waitForCrawlerMessage(int rabbitTimeout) throws Exception {
        logger.info("Waiting for jobs from Crawler...");
        try(Connection connection = factory.newConnection();
            Channel channel = connection.createChannel()){
            channel.queueDeclare(inputQueue, false, false, false, null);

            BlockingQueue<List<String>> messageQueue = new ArrayBlockingQueue<>(1);

            DeliverCallback deliverCallback = (consumerTag, delivery) -> {
                String message = new String(delivery.getBody(), StandardCharsets.UTF_8);
                List<String> parsedIds = parseIds(message);
                messageQueue.offer(parsedIds);
            };
            channel.basicConsume(inputQueue, true, deliverCallback, consumerTag -> { });
            if (rabbitTimeout > 0) {
                return messageQueue.poll(rabbitTimeout, TimeUnit.SECONDS);
            } else { // negative number means we don't have a timeout and we'll wait as long as we need to
                return messageQueue.take();
            }

        } catch (TimeoutException e) {
            logger.error("Error occurred while sending the Reconciler message to RabbitMQ: {}", e.getMessage());
            return null;
        } catch (IOException e) {
            logger.error(e.getMessage());
            throw new RuntimeException(e);
        }
    }

    /**
     * Sends the list of Ids to the PNE
     * @param msg
     */
    public void sendPNEMessage(PNEInputMessage msg) {

        try (Connection connection = factory.newConnection();
             Channel channel = connection.createChannel()) {
            channel.queueDeclare(outputQueue, false, false, false, null);
            String message = genJson(msg);
            channel.basicPublish("", outputQueue, null, message.getBytes(StandardCharsets.UTF_8));

        } catch (TimeoutException | IOException e) {
            logger.error("Error occurred while sending the PNE message to RabbitMQ: {}", e.getMessage());
        }
    }

    /**
     * Parses ids from JsonString
     * @param jsonString
     * @return
     */
    @SuppressWarnings("unchecked")
    public List<String> parseIds(String jsonString) {
        try {
            logger.info("incoming cve list: {}", jsonString);
            return OM.readValue(jsonString, ArrayList.class);
        } catch (JsonProcessingException e) {
            logger.error("Failed to parse list of ids from json string: {}", e.toString());
            return null;
        }
    }

    /**
     * generates the json string from the list of strings
     * @param msg
     * @return
     */
    private String genJson(PNEInputMessage msg) {
        try {
            return OM.writeValueAsString(msg);
        } catch (JsonProcessingException e) {
            logger.error("Failed to convert list of ids to json string: {}", e.toString());
            return "";
        }
    }
}
