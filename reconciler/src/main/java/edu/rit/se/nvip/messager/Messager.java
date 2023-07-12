package edu.rit.se.nvip.messager;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import com.rabbitmq.client.Channel;
import com.rabbitmq.client.Connection;
import com.rabbitmq.client.ConnectionFactory;
import com.rabbitmq.client.DeliverCallback;
import edu.rit.se.nvip.DatabaseHelper;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.*;

public class Messager {

    private final static String RECONCILER_QUEUE = "CRAWLER_OUT";
    private final static String PNE_QUEUE = "RECONCILER_OUT";
    private static final Logger logger = LogManager.getLogger(DatabaseHelper.class.getSimpleName());
    private ConnectionFactory factory;

    public Messager(){
        this.factory = new ConnectionFactory();
        factory.setHost("localhost");
        factory.setUsername("guest");
        factory.setPassword("guest");
    }

    public void setFactory(ConnectionFactory factory) {
        this.factory = factory;
    }

    public List<String> waitForCrawlerMessage(int rabbitTimeout) {

        try (Connection connection = factory.newConnection();
             Channel channel = connection.createChannel()) {
            channel.queueDeclare(RECONCILER_QUEUE, false, false, false, null);

            BlockingQueue<List<String>> messageQueue = new ArrayBlockingQueue<>(1);

            DeliverCallback deliverCallback = (consumerTag, delivery) -> {
                String message = new String(delivery.getBody(), StandardCharsets.UTF_8);
                List<String> parsedIds = parseIds(message);
                messageQueue.offer(parsedIds);
            };
            channel.basicConsume(RECONCILER_QUEUE, true, deliverCallback, consumerTag -> {
            });

            return messageQueue.poll(rabbitTimeout, TimeUnit.SECONDS);

        } catch (TimeoutException e) {
            logger.error("Error occurred while sending the Reconciler message to RabbitMQ: {}", e.getMessage());
        } catch (IOException | InterruptedException e) {
            throw new RuntimeException(e);
        }


        return null;
    }

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
}
