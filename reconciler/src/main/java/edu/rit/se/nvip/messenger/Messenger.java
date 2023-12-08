/**
* Copyright 2021 Rochester Institute of Technology (RIT). Developed with
* government support under contract 70RCSA22C00000008 awarded by the United
* States Department of Homeland Security for Cybersecurity and Infrastructure Security Agency.
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the “Software”), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in
* all copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE.
*/

package edu.rit.se.nvip.messenger;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.rabbitmq.client.Channel;
import com.rabbitmq.client.Connection;
import com.rabbitmq.client.ConnectionFactory;
import com.rabbitmq.client.DeliverCallback;
import edu.rit.se.nvip.ReconcilerController;
import edu.rit.se.nvip.db.DatabaseHelper;
import edu.rit.se.nvip.db.model.CompositeVulnerability;
import edu.rit.se.nvip.utils.ReconcilerEnvVars;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.concurrent.TimeoutException;

public class Messenger {

    private final String inputQueue;
    private final String outputQueue;
    private static final Logger logger = LogManager.getLogger(Messenger.class);
    private static final ObjectMapper OM = new ObjectMapper();
    private ConnectionFactory factory;

    private ReconcilerController rc;

    public Messenger(){
        // Instantiate with default values
        this(
                ReconcilerEnvVars.getRabbitHost(),
                ReconcilerEnvVars.getRabbitVHost(),
                ReconcilerEnvVars.getRabbitPort(),
                ReconcilerEnvVars.getRabbitUsername(),
                ReconcilerEnvVars.getRabbitPassword(),
                ReconcilerEnvVars.getRabbitQueueIn(),
                ReconcilerEnvVars.getRabbitQueueOut());
    }

    public Messenger(ConnectionFactory factory, String inputQueue, String outputQueue, ReconcilerController rc){
        this.factory = factory;
        this.inputQueue = inputQueue;
        this.outputQueue = outputQueue;
        this.rc = rc;
    }


    /**
     * Instantiate new RabbitMQ Messenger
     * @param host hostname
     * @param username username
     * @param password password
     */
    public Messenger(String host, String vhost, int port, String username, String password, String inputQueue, String outputQueue){
        logger.info("Creating RabbitMQ Connection to following url: {}:{}/{}", host, port, vhost);
        factory = new ConnectionFactory();
        factory.setHost(host);
        factory.setVirtualHost(vhost);
        factory.setPort(port);
        factory.setUsername(username);
        factory.setPassword(password);

        try {
            factory.useSslProtocol();
        } catch (NoSuchAlgorithmException e) {
            logger.error(e.getMessage());
            throw new RuntimeException(e);
        } catch (KeyManagementException e) {
            logger.error(e.getMessage());
            throw new RuntimeException(e);
        }

        this.inputQueue = inputQueue;
        this.outputQueue = outputQueue;
    }

    public void run(){

        DatabaseHelper dbh = DatabaseHelper.getInstance();
        if (!dbh.testDbConnection()) {
            logger.error("Error in database connection! Please check if the database configured in DB Envvars is up and running!");
            System.exit(1);
        }

        logger.info("Waiting for jobs from Crawler...");
        try {
            Connection connection = factory.newConnection();
            Channel channel = connection.createChannel();
            channel.queueDeclare(inputQueue, true, false, false, null);
            channel.queueDeclare(outputQueue, true, false, false, null);

            DeliverCallback deliverCallback = (consumerTag, delivery) -> {
                String message = new String(delivery.getBody(), StandardCharsets.UTF_8);
                Set<String> parsedIds = new HashSet<>(parseIds(message));
                Set<CompositeVulnerability> reconciledVulns = rc.reconcileCves(parsedIds);
                reconciledVulns.stream()
                        .filter(v -> v.getReconciliationStatus() == CompositeVulnerability.ReconciliationStatus.NEW ||
                                v.getReconciliationStatus() == CompositeVulnerability.ReconciliationStatus.UPDATED)
                        .map(CompositeVulnerability::getVersionId)
                        .forEach(vuln -> {
                            try {
                                channel.basicPublish("", outputQueue, null, genJson(vuln).getBytes(StandardCharsets.UTF_8));
                            } catch (IOException e) {
                                throw new RuntimeException(e);
                            }
                        });
                try { rc.characterizeCves(reconciledVulns); }
                catch (Exception e) { logger.error(e.toString()); }
                try { rc.updateTimeGaps(reconciledVulns); }
                catch (Exception e) { logger.error(e.toString()); }
                try { rc.createRunStats(reconciledVulns); }
                catch (Exception e) { logger.error(e.toString()); }
            };
            channel.basicConsume(inputQueue, true, deliverCallback, consumerTag -> { });

        } catch (TimeoutException e) {
            logger.error("Error occurred while sending the Reconciler message to RabbitMQ: {}", e.getMessage());
        } catch (IOException e) {
            logger.error(e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * Used in tests to set a mock factory
     * @param factory
     */
    public void setFactory(ConnectionFactory factory) {
        this.factory = factory;
    }

    /**
     * Parses ids from JsonString
     * @param jsonString
     * @return
     */
    @SuppressWarnings("unchecked")
    public List<String> parseIds(String jsonString) {
        try {
            logger.info("incoming cve list: {}", jsonString);
            return OM.readValue(jsonString, ArrayList.class);
        } catch (JsonProcessingException e) {
            logger.error("Failed to parse list of ids from json string: {}", e.toString());
            return null;
        }
    }

    /**
     * generates the json string from the list of strings
     * @param vulnVersionId
     * @return
     */
    private String genJson(int vulnVersionId) {
        try {
            logger.info("about to send a vuln version id of {}", String.valueOf(vulnVersionId));
            Map<String, String> cveJson = Map.of("vulnVersionId", String.valueOf(vulnVersionId));
            return OM.writeValueAsString(cveJson);
        } catch (JsonProcessingException e) {
            logger.error("Failed to convert list of ids to json string: {}", e.toString());
            return "";
        }
    }
}
