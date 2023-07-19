package messenger;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.rabbitmq.client.Channel;
import com.rabbitmq.client.Connection;
import com.rabbitmq.client.ConnectionFactory;
import com.rabbitmq.client.DeliverCallback;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import env.ProductNameExtractorEnvVars;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.*;

public class Messenger {
    private final static String INPUT_QUEUE = "RECONCILER_OUT";
    private final static String OUTPUT_QUEUE = "PNE_OUT";
    private static final Logger logger = LogManager.getLogger(Messenger.class.getSimpleName());
    private static final ObjectMapper OM = new ObjectMapper();
    private final ConnectionFactory factory;

    public Messenger(){
        // Instantiate with default values
        this(
                ProductNameExtractorEnvVars.getRabbitHost(),
                ProductNameExtractorEnvVars.getRabbitUsername(),
                ProductNameExtractorEnvVars.getRabbitPassword()
        );
    }

    /**
     * Instantiate new RabbitMQ Messenger
     * @param host hostname
     * @param username username
     * @param password password
     */
    public Messenger(String host, String username, String password){
        factory = new ConnectionFactory();
        factory.setHost(host);
        factory.setUsername(username);
        factory.setPassword(password);
    }

    public List<String> waitForReconcilerMessage(int pollInterval) {
        // Initialize job list
        List<String> cveIds = null;
        logger.info("Waiting for jobs from Reconciler...");
        final long startTime = System.currentTimeMillis();

        // Busy-wait loop for jobs
        while(cveIds == null) {
            try(Connection connection = factory.newConnection();
                Channel channel = connection.createChannel()){

                channel.queueDeclare(INPUT_QUEUE, false, false, false, null);

                BlockingQueue<List<String>> messageQueue = new ArrayBlockingQueue<>(1);

                DeliverCallback deliverCallback = (consumerTag, delivery) -> {
                    String message = new String(delivery.getBody(), StandardCharsets.UTF_8);

                    // If FINISHED or TERMINATE sent, just offer a 1 element list with the message
                    if(message.equals("FINISHED") || message.equals("TERMINATE")) {
                        List<String> noJobs = new ArrayList<>();
                        noJobs.add(message);
                        messageQueue.offer(noJobs);

                    // Otherwise jobs were sent, parseIds and then offer the list of jobs
                    } else {
                        List<String> parsedIds = parseIds(message);
                        if(parsedIds.size() > 0 && !messageQueue.offer(parsedIds)) logger.error("Job response could not be added to message queue");
                    }

                };

                channel.basicConsume(INPUT_QUEUE, true, deliverCallback, consumerTag -> { });

                logger.info("Polling message queue...");
                cveIds = messageQueue.poll(pollInterval, TimeUnit.SECONDS);
                final long elapsedTime = System.currentTimeMillis() - startTime;

                // Status log every 10 minutes
                if(elapsedTime / 1000 % 600 == 0){
                    logger.info("Messenger has been waiting for a message for {} minute(s)", elapsedTime / 1000 / 60);
                }

            } catch (TimeoutException | InterruptedException | IOException e) {
                logger.error("Error occurred while getting jobs from the ProductNameExtractor: {}", e.toString());
                break;
            }
        }

        return cveIds;
    }

    public void sendPatchFinderMessage(List<String> cveIds) {

        try (Connection connection = factory.newConnection();
             Channel channel = connection.createChannel()) {
            channel.queueDeclare(OUTPUT_QUEUE, false, false, false, null);
            String message = genJson(cveIds);
            channel.basicPublish("", OUTPUT_QUEUE, null, message.getBytes(StandardCharsets.UTF_8));

        } catch (TimeoutException | IOException e) {
            logger.error("Error occurred while sending the PNE message to RabbitMQ: {}", e.getMessage());
        }
    }

    public void sendPatchFinderFinishMessage() {

        try (Connection connection = factory.newConnection();
             Channel channel = connection.createChannel()) {
            channel.queueDeclare(OUTPUT_QUEUE, false, false, false, null);
            String message = "FINISHED";
            channel.basicPublish("", OUTPUT_QUEUE, null, message.getBytes(StandardCharsets.UTF_8));

        } catch (TimeoutException | IOException e) {
            logger.error("Error occurred while sending the PNE message to RabbitMQ: {}", e.getMessage());
        }
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

    private String genJson(List<String> cveIds) {
        try {
            return OM.writeValueAsString(cveIds);
        } catch (JsonProcessingException e) {
            logger.error("Failed to convert list of ids to json string: {}", e.toString());
            return "";
        }
    }

    private void sendDummyMessage(String queue, List<String> cveIds) {
        try (Connection connection = factory.newConnection();
             Channel channel = connection.createChannel()) {
            channel.queueDeclare(queue, false, false, false, null);
            String message = genJson(cveIds);
            channel.basicPublish("", queue, null, message.getBytes(StandardCharsets.UTF_8));
        } catch (IOException | TimeoutException e) {}
    }

    public static void main(String[] args) {
        Messenger messenger = new Messenger();
        List<String> cveIds = new ArrayList<>();
//        cveIds.add("CVE-2020-28468");
        cveIds.add("TERMINATE");
        messenger.sendDummyMessage(INPUT_QUEUE, cveIds);

    }
}
