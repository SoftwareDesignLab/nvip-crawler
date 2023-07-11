package messenger;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.rabbitmq.client.Channel;
import com.rabbitmq.client.Connection;
import com.rabbitmq.client.ConnectionFactory;
import com.rabbitmq.client.DeliverCallback;
import db.DatabaseHelper;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.*;

public class Messenger {
    private final static String INPUT_QUEUE = "patchfinder";
//    private final static String OUTPUT_QUEUE = "";
    private static final Logger logger = LogManager.getLogger(DatabaseHelper.class.getSimpleName());
    private static final ObjectMapper OM = new ObjectMapper();
    private ConnectionFactory factory;

    public Messenger(String host, String username, String password) {
        this.factory = new ConnectionFactory();
        factory.setHost(host);
        factory.setUsername(username);
        factory.setPassword(password);
    }

    public void setFactory(ConnectionFactory factory) {
        this.factory = factory;
    }

    public List<String> waitForProductNameExtractorMessage(int rabbitTimeout) throws IOException {
        // Initialize job list
        List<String> jobIds = null;

        try {
            // Busy-wait loop for jobs
            while(jobIds == null) {
                try(Connection connection = factory.newConnection();
                    Channel channel = connection.createChannel()){

                    channel.queueDeclare(INPUT_QUEUE, false, false, false, null);

                    BlockingQueue<List<String>> messageQueue = new ArrayBlockingQueue<>(1);

                    DeliverCallback deliverCallback = (consumerTag, delivery) -> {
                        String message = new String(delivery.getBody(), StandardCharsets.UTF_8);
                        List<String> parsedIds = parseIds(message);
                        if(!messageQueue.offer(parsedIds)) logger.error("Job response could not be added to message queue");
                    };
                    channel.basicConsume(INPUT_QUEUE, true, deliverCallback, consumerTag -> { });

                    jobIds = messageQueue.poll(rabbitTimeout, TimeUnit.SECONDS);

                } catch (TimeoutException | InterruptedException e) {
                    logger.error("Error occurred while getting jobs from the ProductNameExtractor: {}", e.getMessage());
                }
            }
        } catch (IOException e) {
            logger.error("Error occurred while waiting for jobs: {}", e.toString());
        }


        return null;
    }

    @SuppressWarnings("unchecked")
    public List<String> parseIds(String jsonString) {
        try {
            return OM.readValue(jsonString, ArrayList.class);
        } catch (JsonProcessingException e) {
            logger.error("Failed to parse list of ids from json string: {}", e.toString());
            return new ArrayList<>();
        }
    }

    private String genJson(List<String> ids) {
        try {
            return OM.writeValueAsString(ids);
        } catch (JsonProcessingException e) {
            logger.error("Failed to convert list of ids to json string: {}", e.toString());
            return "";
        }
    }

    public static void main(String[] args) {
        final Messenger m = new Messenger("localhost", "guest", "guest");

    }
}
