package edu.rit.se.nvip.openai;

import com.rabbitmq.client.*;
import edu.rit.se.nvip.utils.ReconcilerEnvVars;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
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

    public static void main(String[] args) {
        OpenAIProcessor openAi = new OpenAIProcessor();
        openAi.sendMessage(ReconcilerEnvVars.getOpenAIKey(),
                "You are a calculator",
                "What is 2 + 2",
                0.0);
        String response = openAi.getResponse();
        logger.info(response);
    }
    public OpenAIProcessor(){
        ReconcilerEnvVars.loadVars();
        // Create a connection factory and configure it
        factory = new ConnectionFactory();
        factory.setHost("localhost");
        factory.setUsername("guest");
        factory.setPassword("guest");
    }

    public void sendMessage(String apiKey, String sys_msg, String usr_msg, double temp){
        //Sanitize msgs
        sys_msg = sys_msg.replace("\"", "'");
        usr_msg = usr_msg.replace("\"", "'");
        // Create a connection to the RabbitMQ server
        try(Connection connection = factory.newConnection();
            Channel channel = connection.createChannel()) {
            // Declare the queue
            channel.queueDeclare(OPENAI_SENDER, false, false, false, null);
            // Define the message content
            String message = "{"
                    + "\"openai_api_key\": \"" + apiKey + "\","
                    + "\"system_message\": \""+sys_msg+"\","
                    + "\"user_message\": \""+usr_msg+"\","
                    + "\"temperature\": " + temp
                    + "}";

            // Publish the message to the queue
            channel.basicPublish("", OPENAI_SENDER, null, message.getBytes());

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
