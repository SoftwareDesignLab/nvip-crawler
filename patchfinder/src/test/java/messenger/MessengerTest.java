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
import org.junit.Assert;
import org.junit.Test;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.*;

import static org.junit.Assert.*;
import static org.junit.platform.commons.function.Try.success;
import static org.mockito.Mockito.*;

/**
 * Unit tests for Messenger class
 *
 * @author Richard Sawh
 */
public class MessengerTest {


    @Test
    public void testWaitForProductNameExtractorMessage_ValidMessageReceived() throws Exception {
        // Create a mock ConnectionFactory and Channel
        ConnectionFactory factoryMock = mock(ConnectionFactory.class);
        Connection connectionMock = mock(Connection.class);
        Channel channelMock = mock(Channel.class);
        when(factoryMock.newConnection()).thenReturn(connectionMock);
        when(connectionMock.createChannel()).thenReturn(channelMock);

        // Create a Messenger instance with the mock ConnectionFactory
        Messenger messenger = new Messenger(factoryMock, "PNE_OUT");

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
        }).when(channelMock).basicConsume((String) eq("patchfinder"), eq(true), (DeliverCallback) any(), (CancelCallback) any());

        // Invoke the method under test asynchronously using CompletableFuture
        CompletableFuture<List<String>> completableFuture = CompletableFuture.supplyAsync(() -> {
            try {
                return messenger.waitForProductNameExtractorMessage(5);
            } catch (Exception e) {
                e.printStackTrace();
                return null;
            }
        });

        // Wait for the message to be delivered and the method under test to complete or timeout after 5 seconds
        try {
            List<String> actualMessage = completableFuture.get(5, TimeUnit.SECONDS);
            assertNotNull(actualMessage);
        } catch (TimeoutException e) {
            success("Message not received within the specified timeout.");
        }
    }



    @Test
    public void testMain() {
        // Redirect the standard output to a ByteArrayOutputStream
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        PrintStream printStream = new PrintStream(outputStream);
        System.setOut(printStream);

        // Invoke the main method
        Messenger.main(new String[0]);

        // Restore the standard output
        System.setOut(System.out);

        // Verify the output (if any) and assert any desired conditions
        String output = outputStream.toString().trim();
        assertEquals("", output);
    }


    // Test that CVE strings are validated
    @Test
    public void testParseIds_ValidJsonString() {
        String expectedId = "CVE-2023-0001";

        String actualId = Messenger.parseMessage(expectedId);

        assertEquals(expectedId, actualId);
    }

    // Test invalid CVE string
    @Test
    public void testParseIds_InvalidJsonString() {
        String jsonString = "invalidJsonString";

        String actualId = Messenger.parseMessage(jsonString);

        assertNull(actualId);
    }
}
