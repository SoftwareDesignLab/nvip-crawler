package messenger;

/**
 * Copyright 2023 Rochester Institute of Technology (RIT). Developed with
 * government support under contract 70RSAT19CB0000020 awarded by the United
 * States Department of Homeland Security.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

import com.fasterxml.jackson.databind.ObjectMapper;
import com.rabbitmq.client.*;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.*;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.platform.commons.function.Try.success;
import static org.mockito.Mockito.*;

/**
 * Unit tests for Messenger class
 *
 * @author Richard Sawh
 */
public class MessengerTest {
    @Test
    public void testWaitForReconcilerMessage_ValidMessageReceived() throws Exception {
        // Create a mock ConnectionFactory and Channel
        ConnectionFactory factoryMock = mock(ConnectionFactory.class);
        Connection connectionMock = mock(Connection.class);
        Channel channelMock = mock(Channel.class);
        when(factoryMock.newConnection()).thenReturn(connectionMock);
        when(connectionMock.createChannel()).thenReturn(channelMock);

        // Create a Messenger instance with the mock ConnectionFactory
        Messenger messenger = new Messenger("localhost", "/", 5672,"guest", "guest", "RECONCILER_OUT", "PNE_OUT");
        messenger.setFactory(factoryMock);

        // Create a message queue and a message to be received
        BlockingQueue<List<String>> messageQueue = new ArrayBlockingQueue<>(1);
        List<String> expectedMessage = Arrays.asList("job1", "job2");
        ObjectMapper objectMapper = new ObjectMapper();
        String jsonMessage = objectMapper.writeValueAsString(expectedMessage);

        // Set up the mock channel to deliver the message
        doAnswer(invocation -> {
            String consumerTag = invocation.getArgument(0);
            DeliverCallback deliverCallback = invocation.getArgument(2);
            deliverCallback.handle(consumerTag, new Delivery(null, null, jsonMessage.getBytes()));
            return consumerTag;
        }).when(channelMock).basicConsume((String) eq("productnameextractor"), eq(true), (DeliverCallback) any(), (CancelCallback) any());

        // Invoke the method under test asynchronously using CompletableFuture
        CompletableFuture<PNEInputMessage> completableFuture = CompletableFuture.supplyAsync(() -> {
            try {
                return messenger.waitForReconcilerMessage(5);
            } catch (Exception e) {
                e.printStackTrace();
                return null;
            }
        });

        // Wait for the message to be delivered and the method under test to complete or timeout after 5 seconds
        try {
            PNEInputMessage actualMessage = completableFuture.get(5, TimeUnit.SECONDS);
            assertNotNull(actualMessage);
        } catch (TimeoutException e) {
            success("Message not received within the specified timeout.");
        }
    }

    @Test
    public void testParseIds_ValidJsonString() {
        Messenger messenger = new Messenger("localhost", "/", 5672,"guest", "guest", "RECONCILER_OUT", "PNE_OUT");
        String jsonString = "{\"jobs\":[{\"cveId\":\"id1\"},{\"cveId\":\"id2\"},{\"cveId\":\"id3\"}]}";
        List<String> expectedIds = Arrays.asList("id1", "id2", "id3");

        PNEInputMessage msg = messenger.parseInput(jsonString);
        List<String> actualIds = msg.getJobs().stream().map(PNEInputJob::getCveId).collect(Collectors.toList());

        assertEquals(expectedIds, actualIds);
    }

    @Test
    public void testParseIds_InvalidJsonString() {
        Messenger messenger = new Messenger("localhost", "/", 5672,"guest", "guest", "RECONCILER_OUT", "PNE_OUT");
        String jsonString = "invalidJsonString";

        PNEInputMessage msg = messenger.parseInput(jsonString);
        List<String> actualIds = msg.getJobs().stream().map(PNEInputJob::getCveId).collect(Collectors.toList());

        assertNotNull(actualIds);
        assertTrue(actualIds.isEmpty());
    }


    @Test
    public void testSendPatchFinderMessage() throws IOException, TimeoutException {
        // Arrange
        Messenger messenger = new Messenger();
        ConnectionFactory factory = mock(ConnectionFactory.class);
        messenger.setFactory(factory);

        when(factory.newConnection()).thenReturn(mock(Connection.class));
        Channel channel = mock(Channel.class);
        when(factory.newConnection().createChannel()).thenReturn(channel);

        String queueName = "PNE_OUT";
        List<PFInputJob> jobs = new ArrayList<>();
        jobs.add(new PFInputJob("CVE-2023-0001", 1));
        jobs.add(new PFInputJob("CVE-2023-0002", 2));
        PFInputMessage msg = new PFInputMessage("NORMAL", jobs);

        // Act
        messenger.sendPatchFinderMessage(msg);

        // Assert
        String expectedMessage = msg.toString();
        verify(channel, times(1)).queueDeclare(
                eq(queueName),
                eq(false),
                eq(false),
                eq(false),
                isNull()
        );
        verify(channel, times(1)).basicPublish(
                eq(""),
                eq(queueName),
                isNull(),
                eq(expectedMessage.getBytes(StandardCharsets.UTF_8))
        );
    }

    @Test
    public void testSendPatchFinderFinishMessage() throws IOException, TimeoutException {
        // Arrange
        Messenger messenger = new Messenger();
        ConnectionFactory factory = mock(ConnectionFactory.class);
        messenger.setFactory(factory);

        Connection connection = mock(Connection.class);
        Channel channel = mock(Channel.class);

        when(factory.newConnection()).thenReturn(connection);
        when(connection.createChannel()).thenReturn(channel);

        String queueName = "PNE_OUT";
        PFInputMessage msg = new PFInputMessage("FINISHED", new ArrayList<>());
        byte[] messageBytes = msg.toString().getBytes(StandardCharsets.UTF_8);

        // Act
        messenger.sendPatchFinderFinishMessage();

        // Assert
        verify(channel, times(1)).queueDeclare(eq(queueName), eq(false), eq(false), eq(false), isNull());
        verify(channel, times(1)).basicPublish(eq(""), eq(queueName), isNull(), eq(messageBytes));
    }

    @Test
    public void testMain(){
        //timeout after 15 seconds
        Messenger messenger = new Messenger("localhost", "/", 5672,"guest", "guest", "RECONCILER_OUT", "PNE_OUT");

        //create a thread to run the messenger
        Thread thread = new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    messenger.main(new String[]{"localhost", "guest", "guest"});
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        });
        thread.start();

        //wait for the thread to finish
        try {
            thread.join(15000);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        assertFalse(thread.isAlive());
    }

}

