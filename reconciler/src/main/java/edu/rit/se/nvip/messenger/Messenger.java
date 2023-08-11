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

    private final static String RECONCILER_QUEUE = "CRAWLER_OUT"; //likely needs to be updated
    private final static String PNE_QUEUE = "RECONCILER_OUT"; //likely needs to be updated
    private static final Logger logger = LogManager.getLogger(DatabaseHelper.class.getSimpleName());
    private static final ObjectMapper OM = new ObjectMapper();
    private ConnectionFactory factory;

    public Messenger(){
        // Instantiate with default values
        this(ReconcilerEnvVars.getRabbitHost(), ReconcilerEnvVars.getRabbitUsername(), ReconcilerEnvVars.getRabbitPassword());
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
            channel.queueDeclare(RECONCILER_QUEUE, false, false, false, null);

            BlockingQueue<List<String>> messageQueue = new ArrayBlockingQueue<>(1);

            DeliverCallback deliverCallback = (consumerTag, delivery) -> {
                String message = new String(delivery.getBody(), StandardCharsets.UTF_8);
                List<String> parsedIds = parseIds(message);
                messageQueue.offer(parsedIds);
            };
            channel.basicConsume(RECONCILER_QUEUE, true, deliverCallback, consumerTag -> { });
            if (rabbitTimeout > 0) {
                return messageQueue.poll(rabbitTimeout, TimeUnit.SECONDS);
            } else { // negative number means we don't have a timeout and we'll wait as long as we need to
                return messageQueue.take();
            }

        } catch (TimeoutException e) {
            logger.error("Error occurred while sending the Reconciler message to RabbitMQ: {}", e.getMessage());
        }

        return null;
    }

    /**
     * Sends the list of Ids to the PNE
     * @param ids
     */
    public void sendPNEMessage(List<String> ids) {

        try (Connection connection = factory.newConnection();
             Channel channel = connection.createChannel()) {
            channel.queueDeclare(PNE_QUEUE, false, false, false, null);
            String message = genJson(ids);
            channel.basicPublish("", PNE_QUEUE, null, message.getBytes(StandardCharsets.UTF_8));

        } catch (TimeoutException | IOException e) {
            logger.error("Error occurred while sending the PNE message to RabbitMQ: {}", e.getMessage());
        }
    }

    /**
     * Sends the "FINISHED" flag so that the PNE knows there are no more Ids being sent
     */
    public void sendPNEFinishMessage() {

        try (Connection connection = factory.newConnection();
             Channel channel = connection.createChannel()) {
            channel.queueDeclare(PNE_QUEUE, false, false, false, null);
            String message = "FINISHED";
            channel.basicPublish("", PNE_QUEUE, null, message.getBytes(StandardCharsets.UTF_8));

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
            return OM.readValue(jsonString, ArrayList.class);
        } catch (JsonProcessingException e) {
            logger.error("Failed to parse list of ids from json string: {}", e.toString());
            return new ArrayList<>();
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
