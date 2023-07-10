package edu.rit.se.nvip.messenger;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import com.rabbitmq.client.Channel;
import com.rabbitmq.client.Connection;
import com.rabbitmq.client.ConnectionFactory;
import com.rabbitmq.client.DeliverCallback;
import edu.rit.se.nvip.db.DatabaseHelper;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.*;

public class Messenger {
    private final static String PNE_QUEUE = "reconciler";
    private final static String PATCHFINDER_QUEUE = "patchfinder";
    private static final Logger logger = LogManager.getLogger(DatabaseHelper.class.getSimpleName());
    private ConnectionFactory factory;

    public Messenger(){
        this.factory = new ConnectionFactory();
        factory.setHost("localhost");
        factory.setUsername("guest");
        factory.setPassword("guest");
    }

    public void setFactory(ConnectionFactory factory) {
        this.factory = factory;
    }

    public List<String> waitForReconcilerMessage(int rabbitTimeout) throws Exception {
        try(Connection connection = factory.newConnection();
            Channel channel = connection.createChannel()){
            channel.queueDeclare(PNE_QUEUE, false, false, false, null);

            BlockingQueue<List<String>> messageQueue = new ArrayBlockingQueue<>(1);

            DeliverCallback deliverCallback = (consumerTag, delivery) -> {
                String message = new String(delivery.getBody(), StandardCharsets.UTF_8);
                List<String> parsedIds = parseIds(message);
                messageQueue.offer(parsedIds);
            };
            channel.basicConsume(PNE_QUEUE, true, deliverCallback, consumerTag -> { });

            return messageQueue.poll(rabbitTimeout, TimeUnit.SECONDS);

        } catch (TimeoutException e) {
            logger.error("Error occurred while sending the Reconciler message to RabbitMQ: {}", e.getMessage());
        }

        return null;
    }

    public void sendPatchfinderMessage(List<String> ids) {

        try (Connection connection = factory.newConnection();
             Channel channel = connection.createChannel()) {
            channel.queueDeclare(PATCHFINDER_QUEUE, false, false, false, null);
            String message = genJson(ids);
            channel.basicPublish("", PATCHFINDER_QUEUE, null, message.getBytes(StandardCharsets.UTF_8));

        } catch (TimeoutException | IOException e) {
            logger.error("Error occurred while sending the PNE message to RabbitMQ: {}", e.getMessage());
        }
    }

    public void sendPatchfinderFinishMessage() {

        try (Connection connection = factory.newConnection();
             Channel channel = connection.createChannel()) {
            channel.queueDeclare(PATCHFINDER_QUEUE, false, false, false, null);
            String message = "FINISHED";
            channel.basicPublish("", PATCHFINDER_QUEUE, null, message.getBytes(StandardCharsets.UTF_8));

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
