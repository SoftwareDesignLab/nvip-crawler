package edu.rit.se.nvip.sandbox;

import com.rabbitmq.client.*;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeoutException;

public class SandboxPNE {

    private static final String QUEUE_NAME = "RECONCILER_OUT";

    public static void main() {
        //wait for rabbit message from reconciler

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
                public void handleDelivery(String consumerTag, Envelope envelope, AMQP.BasicProperties properties, byte[] body) throws UnsupportedEncodingException {
                    String message = new String(body, StandardCharsets.UTF_8);
                    System.out.println("Received message: " + message);
                }
            };

            // Start consuming messages from the queue
            channel.basicConsume(QUEUE_NAME, true, consumer);
        } catch (IOException | TimeoutException e) {
            throw new RuntimeException(e);
        }



    }
}
