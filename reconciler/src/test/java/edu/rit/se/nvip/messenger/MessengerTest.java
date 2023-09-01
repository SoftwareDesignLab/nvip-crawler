package edu.rit.se.nvip.messenger;

import com.rabbitmq.client.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.TimeoutException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class MessengerTest {

    private ByteArrayOutputStream outputStream;
    private final static String PNE_QUEUE = "RECONCILER_OUT";
    @Mock
    ConnectionFactory factoryMock = mock(ConnectionFactory.class);
    @Mock
    Connection conn = mock(Connection.class);
    @Mock
    Channel channelMock = mock(Channel.class);


    @BeforeEach
    void setUp() {
        outputStream = new ByteArrayOutputStream();
        System.setOut(new PrintStream(outputStream));
    }

    //assures we can receive messages from rabbit
    @Test
    void waitForCrawlerMessageTest() throws Exception {
        //Setup
        Messenger messenger = new Messenger();
        messenger.setFactory(factoryMock);
        List<String> expectedMessages = new ArrayList<>();
        expectedMessages.add("Test message");
        expectedMessages.add("Test message2");

        //Mocking
        when(factoryMock.newConnection()).thenReturn(conn);
        when(conn.createChannel()).thenReturn(channelMock);
        when(channelMock.queueDeclare(anyString(), anyBoolean(), anyBoolean(), anyBoolean(), any())).thenReturn(null);
        doAnswer(invocation -> {
            Object[] args = invocation.getArguments();
            DeliverCallback callback = (DeliverCallback) args[2];
            String jsonMessage = "{\"cveIds\":[\"Test message\", \"Test message2\"],\"override\":false}";
            byte[] body = jsonMessage.getBytes();
            callback.handle("", new Delivery(null, null, body));
            return null;
        }).when(channelMock).basicConsume(anyString(), anyBoolean(), any(DeliverCallback.class), (CancelCallback) any());

        // Act
        List<String> receivedMessages = messenger.waitForCrawlerMessage(3600).getCveIds();
        List<String> receivedMessages2 = messenger.waitForCrawlerMessage(-1).getCveIds();

        // Assert
        assertEquals(expectedMessages, receivedMessages);
        assertEquals(expectedMessages, receivedMessages2);

    }

    //assures timeout works as expected
    @Test
    void verifyTimeoutTest() throws Exception {
        //Setup
        Messenger messenger = new Messenger();
        messenger.setFactory(factoryMock);
        List<String> expectedMessages = new ArrayList<>();
        expectedMessages.add("Test message");
        expectedMessages.add("Test message2");

        //Mocking
        when(factoryMock.newConnection()).thenReturn(conn);
        when(conn.createChannel()).thenReturn(channelMock);
        when(channelMock.queueDeclare(anyString(), anyBoolean(), anyBoolean(), anyBoolean(), any())).thenReturn(null);

        ReconcilerInputMessage receivedMessages = messenger.waitForCrawlerMessage(1);

        assertEquals(null, receivedMessages);

    }
    //makes sure we can send messages to the PNE
    @Test
    void sendPNEMessageTest() throws IOException, TimeoutException {
        // Setup
        Messenger messenger = new Messenger();
        messenger.setFactory(factoryMock);

        List<String> ids = Arrays.asList("id1", "id2", "id3");

        when(factoryMock.newConnection()).thenReturn(conn);
        when(conn.createChannel()).thenReturn(channelMock);

        // Act
        messenger.sendPNEMessage(ids);

        // Assert
        verify(factoryMock).newConnection();
        verify(conn).createChannel();
        verify(channelMock).queueDeclare(eq(PNE_QUEUE), anyBoolean(), anyBoolean(), anyBoolean(), any());
        verify(channelMock).basicPublish(eq(""), eq(PNE_QUEUE), isNull(), any(byte[].class));
        verify(channelMock).close();
        verify(conn).close();
    }

    //verifies we can properly parse IDs that come in from rabbit
    @Test
    void parseIdsTest() {
        Messenger messenger = new Messenger();
        String jsonString = "{\"cveIds\":[\"id1\", \"id2\", \"id3\"], \"override\":false}";
        List<String> expectedIds = new ArrayList<>();
        expectedIds.add("id1");
        expectedIds.add("id2");
        expectedIds.add("id3");

        ReconcilerInputMessage actualIds = messenger.parseIds(jsonString);
        ReconcilerInputMessage failedToParse = messenger.parseIds("dummy string");

        assertEquals(expectedIds, actualIds.getCveIds());
        assertEquals(null, failedToParse);
    }
}
