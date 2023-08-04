package edu.rit.se.nvip.openai;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;
import com.rabbitmq.client.*;
import edu.rit.se.nvip.utils.ReconcilerEnvVars;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.*;

public class OpenAIProcessor {
    private static final String OPENAI_SENDER = "openai_requests";
    private static final String OPENAI_RECEIVER = "openai_responses";
    private ConnectionFactory factory;
    private static final Logger logger = LogManager.getLogger(OpenAIProcessor.class.getSimpleName());

    private static int nextPriorityId = 0;
    private int jobId = 0;
    private Map<Integer, CompletableFuture<String>> futureMap = new ConcurrentHashMap<>();


    public OpenAIProcessor() {
        ReconcilerEnvVars.loadFromFile();
        // Create a connection factory and configure it
        factory = new ConnectionFactory();
        factory.setHost("localhost");
        factory.setUsername("guest");
        factory.setPassword("guest");
    }

    public void sendRequest(String sys_msg, String usr_msg, double temp, RequestorIdentity requestor) {
        try (Connection connection = factory.newConnection();
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
            message.add("JobID", new JsonPrimitive(jobId++));
            Gson gson = new Gson();
            String jsonString = gson.toJson(message);
            // Publish the message to the queue
            channel.basicPublish("", OPENAI_SENDER, null, jsonString.getBytes());
        } catch (IOException | TimeoutException e) {
            logger.error("Error sending message: " + e);
        }
    }

    public CompletableFuture<String> getResponse() {
        CompletableFuture<String> futureResponse = new CompletableFuture<>();

        try (Connection connection = factory.newConnection();
             Channel channel = connection.createChannel()) {
            // Declare the queue
            channel.queueDeclare(OPENAI_RECEIVER, false, false, false, null);

            // Create a consumer and override the handleDelivery method to complete the future with the received message
            Consumer consumer = new DefaultConsumer(channel) {
                @Override
                public void handleDelivery(String consumerTag, Envelope envelope, AMQP.BasicProperties properties, byte[] body) throws UnsupportedEncodingException {
                    String message = new String(body, StandardCharsets.UTF_8);

                    // Parse the message to check the jobId
                    JsonObject jsonObject = new Gson().fromJson(message, JsonObject.class);
                    int receivedJobId = jsonObject.get("JobID").getAsInt();

                    // Check if the received jobId matches the requested jobId
                    if (receivedJobId == jobId) {
                        // Complete the future with the received message
                        futureResponse.complete(message);
                    } else {
                        // JobId doesn't match, complete the future with an error
                        futureResponse.completeExceptionally(new IllegalArgumentException("Received response for a different jobId."));
                    }
                }
            };

            // Start consuming messages from the queue
            channel.basicConsume(OPENAI_RECEIVER, true, consumer);

        } catch (IOException | TimeoutException e) {
            // Complete the future with an error if there's an exception
            futureResponse.completeExceptionally(e);
        }

        return futureResponse;
    }

}