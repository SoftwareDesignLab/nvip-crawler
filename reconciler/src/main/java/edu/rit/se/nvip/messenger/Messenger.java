package edu.rit.se.nvip.messenger;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.rabbitmq.client.Channel;
import com.rabbitmq.client.Connection;
import com.rabbitmq.client.ConnectionFactory;
import com.rabbitmq.client.DeliverCallback;
import edu.rit.se.nvip.DatabaseHelper;
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
    private static final Logger logger = LogManager.getLogger(DatabaseHelper.class.getSimpleName());
    private static final ObjectMapper OM = new ObjectMapper();
    private ConnectionFactory factory;

    public Messenger(){
        // Instantiate with default values
        this(ReconcilerEnvVars.getRabbitHost(), ReconcilerEnvVars.getRabbitPort(), ReconcilerEnvVars.getRabbitUsername(), ReconcilerEnvVars.getRabbitPassword(),
                ReconcilerEnvVars.getRabbitQueueIn(), ReconcilerEnvVars.getRabbitQueueOut());
    }

    /**
     * Instantiate new RabbitMQ Messenger
     * @param host hostname
     * @param username username
     * @param password password
     */
    public Messenger(String host, int port, String username, String password, String inputQueue, String outputQueue){
        factory = new ConnectionFactory();
        factory.setHost(host);
        factory.setPort(port);
        factory.setUsername(username);
        factory.setPassword(password);
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
        }
    }

    /**
     * Sends the list of Ids to the PNE
     * @param ids
     */
    public void sendPNEMessage(List<String> ids) {

        try (Connection connection = factory.newConnection();
             Channel channel = connection.createChannel()) {
            channel.queueDeclare(outputQueue, false, false, false, null);
            String message = genJson(ids);
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
     * @param ids
     * @return
     */
    private String genJson(List<String> ids) {
        try {
            return OM.writeValueAsString(ids);
        } catch (JsonProcessingException e) {
            logger.error("Failed to convert list of ids to json string: {}", e.toString());
            return "";
        }
    }
}
