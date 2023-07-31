package edu.rit.se.nvip.sandbox;

import com.rabbitmq.client.ConnectionFactory;
import com.rabbitmq.client.Connection;
import com.rabbitmq.client.Channel;
import edu.rit.se.nvip.utils.ReconcilerEnvVars;

import javax.json.Json;
import javax.json.JsonArray;
import javax.json.JsonWriter;
import java.io.StringWriter;
import java.util.Scanner;

public class MessageSenderRabbit {

    private static final String QUEUE_NAME = "openai_requests";

    public static void main(String[] args) throws Exception {
        Scanner scanner = new Scanner(System.in);
        ReconcilerEnvVars.loadFromFile();
        // Create a connection factory and configure it
        ConnectionFactory factory = new ConnectionFactory();
        factory.setHost("localhost");
        factory.setUsername("guest");
        factory.setPassword("guest");
        String msg = "";
        while(!msg.equals("DONE")) {

            // Create a connection to the RabbitMQ server
            try(Connection connection = factory.newConnection();
            Channel channel = connection.createChannel()) {
                // Declare the queue
                channel.queueDeclare(QUEUE_NAME, false, false, false, null);
                // Define the message content
                msg = scanner.nextLine();
                String message = "{"
                        + "\"openai_api_key\": \"" + ReconcilerEnvVars.getOpenAIKey() + "\","
                        + "\"system_message\": \"You are a calculator\","
                        + "\"user_message\": \"" + msg + "\","
                        + "\"temperature\": 0.0"
                        + "}";

                // Publish the message to the queue
                channel.basicPublish("", QUEUE_NAME, null, message.getBytes());
            }
        }
    }
}