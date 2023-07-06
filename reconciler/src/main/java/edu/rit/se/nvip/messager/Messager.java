package edu.rit.se.nvip.messager;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import com.rabbitmq.client.*;
import edu.rit.se.nvip.DatabaseHelper;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeoutException;

public class Messager {

    private final static String QUEUE_NAME = "reconciler";
    private static final Logger logger = LogManager.getLogger(DatabaseHelper.class.getSimpleName());
    private List<String> receivedMessages;
    static boolean messageReceived = false;

    public Messager(){

    }

    public List<String> waitForCrawlerMessage() throws Exception {
        List<String> receivedMessages = new ArrayList<>();

        // Create a connection factory and configure it
        ConnectionFactory factory = new ConnectionFactory();
        factory.setHost("localhost");
        factory.setUsername("guest");
        factory.setPassword("guest");

        // Create connection to the RabbitMQ server
        Connection connection = factory.newConnection();

        // Create channel
        Channel channel = connection.createChannel();

        // Declare the queue
        channel.queueDeclare(QUEUE_NAME, false, false, false, null);

        // Create a consumer and override the handleDelivery method to process received messages
        Consumer consumer = new DefaultConsumer(channel) {
            @Override
            public void handleDelivery(String consumerTag, Envelope envelope, AMQP.BasicProperties properties, byte[] body) throws UnsupportedEncodingException {
                String message = new String(body, StandardCharsets.UTF_8);
                System.out.println("Received message: " + message);

                List<String> parsedIds = parseIds(message);
                receivedMessages.addAll(parsedIds);

                // Acknowledge the message
                try {
                    channel.basicAck(envelope.getDeliveryTag(), false);
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        };

        // Start consuming messages
        channel.basicConsume(QUEUE_NAME, false, consumer);

        // Wait for messages to be received
        while (receivedMessages.isEmpty()) {
            Thread.sleep(100);
        }

        // Close the channel and connection
        channel.close();
        connection.close();

        return receivedMessages;
    }

    public void sendPNEMessage(List<String> ids) throws IOException {
        // Create a connection to RabbitMQ
        ConnectionFactory factory = new ConnectionFactory();
        factory.setHost("localhost"); // Replace with the appropriate RabbitMQ server address if needed
        try (Connection connection = factory.newConnection();
             Channel channel = connection.createChannel()) {

            // Declare the queue
            channel.queueDeclare(QUEUE_NAME, false, false, false, null);

            // Convert the IDs to JSON string
            Gson gson = new Gson();
            String jsonMessage = gson.toJson(ids);

            // Publish the JSON message to the queue
            channel.basicPublish("", QUEUE_NAME, MessageProperties.PERSISTENT_TEXT_PLAIN, jsonMessage.getBytes(StandardCharsets.UTF_8));
        } catch (TimeoutException e) {
            logger.error("Error occurred while sending the PNE message to RabbitMQ: {}", e.getMessage());
        }
    }

    public List<String> parseIds(String jsonString) {

        List<String> ids = new ArrayList<>();
        JsonArray jsonArray = JsonParser.parseString(jsonString).getAsJsonArray();

        for (JsonElement jsonElement : jsonArray) {
            String id = jsonElement.getAsString();
            ids.add(id);
        }

        return ids;
    }

    private String genJson(List<String> ids) {
        Gson gson = new Gson();
        return gson.toJson(ids);
    }
    public List<String> getReceivedMessages() {
        return receivedMessages;
    }
}
