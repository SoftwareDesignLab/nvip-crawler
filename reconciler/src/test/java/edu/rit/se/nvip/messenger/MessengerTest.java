package edu.rit.se.nvip.messenger;

import com.rabbitmq.client.*;
import edu.rit.se.nvip.ReconcilerController;
import edu.rit.se.nvip.model.CompositeVulnerability;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeoutException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class MessengerTest {

    private ByteArrayOutputStream outputStream;
    private final static String PNE_QUEUE = "RECONCILER_OUT";
    @Mock
    ConnectionFactory factoryMock = mock(ConnectionFactory.class);
    @Mock
    Connection mockConn = mock(Connection.class);
    @Mock
    Channel channelMock = mock(Channel.class);


    @BeforeEach
    void setUp() {
        outputStream = new ByteArrayOutputStream();
        System.setOut(new PrintStream(outputStream));
    }

    @Test
    void testRunNoVulnsReconciled() throws IOException, TimeoutException {
        //Mocking
        ReconcilerController mockRc = mock(ReconcilerController.class);
        when(factoryMock.newConnection()).thenReturn(mockConn);
        when(mockConn.createChannel()).thenReturn(channelMock);
        when(channelMock.queueDeclare(anyString(), anyBoolean(), anyBoolean(), anyBoolean(), any())).thenReturn(null);
        when(mockRc.main(anySet())).thenReturn(Set.of());

        doAnswer(invocation -> {
            Object[] args = invocation.getArguments();
            DeliverCallback callback = (DeliverCallback) args[2];
            String jsonMessage = "[\"CVE-1234-5678\", \"CVE-1234-5679\"]";
            byte[] body = jsonMessage.getBytes();
            callback.handle("", new Delivery(null, null, body));
            return null;
        }).when(channelMock).basicConsume(anyString(), anyBoolean(), any(DeliverCallback.class), (CancelCallback) any());
        
        Messenger messenger = new Messenger();
        messenger.setReconcilerController(mockRc);
        messenger.setFactory(factoryMock);
        messenger.run();

        verify(channelMock, times(1)).basicConsume(anyString(), anyBoolean(), any(DeliverCallback.class), (CancelCallback) any());
        verify(channelMock, times(0)).basicPublish(anyString(), anyString(), any(), any());
    }

//    @Test
//    void testRunVulnsReconciled() throws IOException, TimeoutException {
//        //Mocking
//        ReconcilerController mockRc = mock(ReconcilerController.class);
//        when(factoryMock.newConnection()).thenReturn(mockConn);
//        when(mockConn.createChannel()).thenReturn(channelMock);
//        when(channelMock.queueDeclare(anyString(), anyBoolean(), anyBoolean(), anyBoolean(), any())).thenReturn(null);
//        when(mockRc.main(anySet())).thenReturn(Set.of(new CompositeVulnerability("CVE-1234-5678")));
//
//        doAnswer(invocation -> {
//            Object[] args = invocation.getArguments();
//            DeliverCallback callback = (DeliverCallback) args[2];
//            String jsonMessage = "[\"CVE-1234-5678\", \"CVE-1234-5679\"]";
//            byte[] body = jsonMessage.getBytes();
//            callback.handle("", new Delivery(null, null, body));
//            return null;
//        }).when(channelMock).basicConsume(anyString(), anyBoolean(), any(DeliverCallback.class), (CancelCallback) any());
//
//        Messenger messenger = new Messenger();
//        messenger.setReconcilerController(mockRc);
//        messenger.setFactory(factoryMock);
//        messenger.run();
//
//        verify(channelMock, times(1)).basicConsume(anyString(), anyBoolean(), any(DeliverCallback.class), (CancelCallback) any());
//        verify(channelMock, times(0)).basicPublish(anyString(), anyString(), any(), any());
//    }

    //verifies we can properly parse IDs that come in from rabbit
    @Test
    void parseIdsTest() {
        Messenger messenger = new Messenger();
        String jsonString = "[\"id1\", \"id2\", \"id3\"]";
        List<String> expectedIds = new ArrayList<>();
        expectedIds.add("id1");
        expectedIds.add("id2");
        expectedIds.add("id3");

        List<String> actualIds = messenger.parseIds(jsonString);
        List<String> failedToParse = messenger.parseIds("dummy string");

        assertEquals(expectedIds, actualIds);
        assertEquals(null, failedToParse);
    }
}
