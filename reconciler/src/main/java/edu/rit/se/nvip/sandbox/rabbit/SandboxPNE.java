package edu.rit.se.nvip.sandbox.rabbit;

import com.rabbitmq.client.*;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;

public class SandboxPNE {

    private static final String QUEUE_NAME = "RECONCILER_OUT";
    private static final String FINISHED_MESSAGE = "FINISHED";
    private static final AtomicBoolean stopFlag = new AtomicBoolean(false);

    public static void main(String[] args) {
        main();
    }

    public static void main() {
        //ALWAYS WAITS FOR A MESSAGE UNTIL "FINISHED" IS SENT THEN IT ENDS THE RABBIT LISTENER
        try {
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
                public void handleDelivery(String consumerTag, Envelope envelope, AMQP.BasicProperties properties, byte[] body) throws IOException {
                    String message = new String(body, StandardCharsets.UTF_8);
                    System.out.println("Received message: " + message);

                    if (message.equals(FINISHED_MESSAGE)) {
                        stopFlag.set(true); // Set the stop flag to true
                    }
                }
            };

            // Start consuming messages from the queue
            channel.basicConsume(QUEUE_NAME, true, consumer);

            // Wait until the stop flag is set or interrupted
            try {
                while (!stopFlag.get()) {
                    Thread.sleep(100); // Adjust the sleep interval as needed
                }
            } catch (InterruptedException e) {
                // Handle the interruption if necessary
                Thread.currentThread().interrupt();
            }

            // Close the channel and connection
            channel.close();
            connection.close();
        } catch (IOException | TimeoutException e) {
            throw new RuntimeException(e);
        }
    }
}