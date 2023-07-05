package edu.rit.se.nvip.sandbox;

import com.rabbitmq.client.*;

import java.io.UnsupportedEncodingException;

public class MessageReceiverRabbit {

    private static final String QUEUE_NAME = "my_queue";

    public static void main(String[] args) throws Exception {
        // Create a connection factory and configure it
        ConnectionFactory factory = new ConnectionFactory();
        factory.setHost("localhost");
        factory.setUsername("guest");
        factory.setPassword("guest");

        // Create a connection to the RabbitMQ server
        Connection connection = factory.newConnection();

        // Create a channel
        Channel channel = connection.createChannel();

        // Declare the queue
        channel.queueDeclare(QUEUE_NAME, false, false, false, null);

        // Create a consumer and override the handleDelivery method to process received messages
        Consumer consumer = new DefaultConsumer(channel) {
            @Override
            public void handleDelivery(String consumerTag, Envelope envelope, AMQP.BasicProperties properties, byte[] body) throws UnsupportedEncodingException {
                String message = new String(body, "UTF-8");
                System.out.println("Received message: " + message);
            }
        };

        // Start consuming messages from the queue
        channel.basicConsume(QUEUE_NAME, true, consumer);
    }
}
