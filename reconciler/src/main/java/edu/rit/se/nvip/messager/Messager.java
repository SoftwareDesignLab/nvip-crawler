package edu.rit.se.nvip.messager;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import com.rabbitmq.client.*;
import edu.rit.se.nvip.DatabaseHelper;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeoutException;

public class Messager {

    private final static String RECONCILER_QUEUE = "reconciler";
    private final static String PNE_QUEUE = "PNE";
    private static final Logger logger = LogManager.getLogger(DatabaseHelper.class.getSimpleName());
    private ConnectionFactory factory;

    public Messager(){

    }

    public List<String> waitForCrawlerMessage() throws Exception {
        List<String> receivedMessages = new ArrayList<>();

        try(Connection connection = factory.newConnection();
        Channel channel = connection.createChannel()){
            channel.queueDeclare(RECONCILER_QUEUE, false, false, false, null);

            DeliverCallback deliverCallback = (consumerTag, delivery) -> {
                String message = new String(delivery.getBody(), StandardCharsets.UTF_8);
                List<String> parsedIds = parseIds(message);
                receivedMessages.addAll(parsedIds);
            };
            channel.basicConsume(RECONCILER_QUEUE, true, deliverCallback, consumerTag -> { });

        } catch (TimeoutException e) {
        logger.error("Error occurred while sending the PNE message to RabbitMQ: {}", e.getMessage());
    }

        return receivedMessages;
    }

    public void sendPNEMessage(List<String> ids) throws IOException {

        try (Connection connection = factory.newConnection();
             Channel channel = connection.createChannel()) {
            channel.queueDeclare(PNE_QUEUE, false, false, false, null);
            String message = genJson(ids);
            channel.basicPublish("", PNE_QUEUE, null, message.getBytes(StandardCharsets.UTF_8));

        } catch (TimeoutException e) {
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
