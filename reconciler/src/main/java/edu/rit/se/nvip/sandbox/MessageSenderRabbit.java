package edu.rit.se.nvip.sandbox;

import com.rabbitmq.client.ConnectionFactory;
import com.rabbitmq.client.Connection;
import com.rabbitmq.client.Channel;

public class MessageSenderRabbit {

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

        // Define the message content
        String message = "test";

        // Publish the message to the queue
        channel.basicPublish("", QUEUE_NAME, null, message.getBytes());

        // Close the channel and connection
        channel.close();
        connection.close();
    }
}