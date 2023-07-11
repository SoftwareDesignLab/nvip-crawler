package messenger;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.rabbitmq.client.*;
import org.junit.Assert;
import org.junit.Test;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

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
        Messenger messenger = new Messenger("localhost", "guest", "guest");
        messenger.setFactory(factoryMock);

        // Create a message queue and a message to be received
        BlockingQueue<List<String>> messageQueue = new ArrayBlockingQueue<>(1);
        List<String> expectedMessage = Arrays.asList("job1", "job2");
        ObjectMapper objectMapper = new ObjectMapper();
        String jsonMessage = objectMapper.writeValueAsString(expectedMessage);

        // Use CountDownLatch to wait for the message to be received
        CountDownLatch latch = new CountDownLatch(1);

        // Set up the mock channel to deliver the message
        doAnswer(invocation -> {
            String consumerTag = invocation.getArgument(0);
            DeliverCallback deliverCallback = invocation.getArgument(2);
            deliverCallback.handle(consumerTag, new Delivery(null, null, jsonMessage.getBytes()));
            latch.countDown(); // Signal that the message has been received
            return consumerTag;
        }).when(channelMock).basicConsume((String) eq("patchfinder"), eq(true), (DeliverCallback) any(), (CancelCallback) any());

        // Invoke the method under test
        AtomicReference<List<String>> actualMessage = new AtomicReference<>();
        Thread thread = new Thread(() -> {
            try {
                actualMessage.set(messenger.waitForProductNameExtractorMessage(5));
            } catch (Exception e) {
                e.printStackTrace();
            }
        });
        thread.start();

        // Wait for the message to be received or timeout after 5 seconds
        boolean messageReceived = latch.await(5, TimeUnit.SECONDS);
        thread.join();

        // Verify the behavior and result
        assertTrue(messageReceived);
        assertNotNull(actualMessage);
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


    @Test
    public void testParseIds_ValidJsonString() {
        Messenger messenger = new Messenger("localhost", "guest", "guest");
        String jsonString = "[\"id1\",\"id2\",\"id3\"]";
        List<String> expectedIds = Arrays.asList("id1", "id2", "id3");

        List<String> actualIds = messenger.parseIds(jsonString);

        assertEquals(expectedIds, actualIds);
    }

    @Test
    public void testParseIds_InvalidJsonString() {
        Messenger messenger = new Messenger("localhost", "guest", "guest");
        String jsonString = "invalidJsonString";

        List<String> actualIds = messenger.parseIds(jsonString);

        assertNotNull(actualIds);
        Assert.assertTrue(actualIds.isEmpty());
    }

}
