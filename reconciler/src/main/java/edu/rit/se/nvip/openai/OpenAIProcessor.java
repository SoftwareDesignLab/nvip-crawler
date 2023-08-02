package edu.rit.se.nvip.openai;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;
import com.rabbitmq.client.*;
import edu.rit.se.nvip.utils.ReconcilerEnvVars;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.json.JSONObject;
import org.nd4j.linalg.api.ops.Op;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeoutException;

public class OpenAIProcessor {
    private static final String OPENAI_SENDER = "openai_requests";
    private static final String OPENAI_RECEIVER = "openai_responses";
    private static ConnectionFactory factory;
    private static final Logger logger = LogManager.getLogger(OpenAIProcessor.class.getSimpleName());

    private int nextPriorityId = 0;
    public OpenAIProcessor(){
        ReconcilerEnvVars.loadVars();
        // Create a connection factory and configure it
        factory = new ConnectionFactory();
        factory.setHost("localhost");
        factory.setUsername("guest");
        factory.setPassword("guest");
    }

    public void sendRequest(String sys_msg, String usr_msg, double temp, RequestorIdentity requestor){
        // Create a connection to the RabbitMQ server
        try(Connection connection = factory.newConnection();
            Channel channel = connection.createChannel()) {
            // Declare the queue
            channel.queueDeclare(OPENAI_SENDER, false, false, false, null);
            // Define the message content
            JsonObject message = new JsonObject();
            message.add("openai_api_key", new JsonPrimitive(ReconcilerEnvVars.getOpenAIKey()));
            message.add("system_message", new JsonPrimitive(sys_msg));
            message.add("user_message", new JsonPrimitive(usr_msg));
            message.add("temperature", new JsonPrimitive(temp));
            message.add("requestorPrioId", new JsonPrimitive(requestor.priority));
            message.add("PrioId", new JsonPrimitive(nextPriorityId++));
            Gson gson = new Gson();
            String jsonString = gson.toJson(message);
            // Publish the message to the queue
            channel.basicPublish("", OPENAI_SENDER, null, jsonString.getBytes());

        } catch (IOException | TimeoutException e) {
            logger.error("Error sending message: " + e);
        }
    }

    public String getResponse() {
        try (Connection connection = factory.newConnection();
             Channel channel = connection.createChannel()) {
            // Declare the queue
            channel.queueDeclare(OPENAI_RECEIVER, false, false, false, null);

            // Create a blocking queue to store the received message
            BlockingQueue<String> receivedMessageQueue = new LinkedBlockingQueue<>();

            // Create a consumer and override the handleDelivery method to store the received message
            Consumer consumer = new DefaultConsumer(channel) {
                @Override
                public void handleDelivery(String consumerTag, Envelope envelope, AMQP.BasicProperties properties, byte[] body) throws UnsupportedEncodingException {
                    String message = new String(body, StandardCharsets.UTF_8);

                    // Put the received message into the queue
                    receivedMessageQueue.offer(message);
                }
            };

            // Start consuming messages from the queue
            channel.basicConsume(OPENAI_RECEIVER, true, consumer);

            // Wait for a message to be received and return it
            return receivedMessageQueue.take();

        } catch (IOException | TimeoutException | InterruptedException e) {
            logger.error("Error sending message: " + e);
            return null;
        }
    }

}
