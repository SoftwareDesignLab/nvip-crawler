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
import db.DatabaseHelper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;
import productdetection.AffectedProductIdentifier;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.platform.commons.function.Try.success;
import static org.mockito.Mockito.*;

/**
 * Unit tests for Messenger class
 *
 * @author Richard Sawh
 */
@ExtendWith(MockitoExtension.class)
public class MessengerTest {

    @Mock ConnectionFactory factoryMock;

    @Mock Connection mockConn;

    @Mock Channel channelMock;

    @Mock AffectedProductIdentifier affectedProductIdentifier;

    @Test
    public void testWaitForReconcilerMessage_ValidMessageReceived() throws Exception {
        when(factoryMock.newConnection()).thenReturn(mockConn);
        when(mockConn.createChannel()).thenReturn(channelMock);

        // Create a Messenger instance with the mock ConnectionFactory
        Messenger messenger = new Messenger(factoryMock, "RECONCILER_OUT", "PNE_OUT_PATCH", "PNE_OUT_FIX", affectedProductIdentifier, mock(DatabaseHelper.class));

        Map<String, String> message = new HashMap<>();
        message.put("cveId", "job1");
        ObjectMapper objectMapper = new ObjectMapper();
        String jsonMessage = objectMapper.writeValueAsString(message);

        // Set up the mock channel to deliver the message
        doAnswer(invocation -> {
            String consumerTag = invocation.getArgument(0);
            DeliverCallback deliverCallback = invocation.getArgument(2);
            deliverCallback.handle(consumerTag, new Delivery(null, null, jsonMessage.getBytes()));
            return consumerTag;
        }).when(channelMock).basicConsume(eq("RECONCILER_OUT"), eq(true), any(DeliverCallback.class), any(CancelCallback.class));

        messenger.run();
        verify(channelMock, times(1)).basicConsume(eq("RECONCILER_OUT"), anyBoolean(), any(DeliverCallback.class), any(CancelCallback.class));
        verify(channelMock, times(1)).basicPublish(anyString(), eq("PNE_OUT"), any(), any());

        verify(affectedProductIdentifier, times(1)).identifyAffectedProducts(any());
    }

    @Test
    public void testWaitForReconcilerMessage_ImproperMessageReceived() throws Exception {
        when(factoryMock.newConnection()).thenReturn(mockConn);
        when(mockConn.createChannel()).thenReturn(channelMock);

        // Create a Messenger instance with the mock ConnectionFactory
        Messenger messenger = new Messenger(factoryMock, "RECONCILER_OUT", "PNE_OUT_PATCH", "PNE_OUT_FIX", affectedProductIdentifier, mock(DatabaseHelper.class));

        Map<String, String> message = new HashMap<>();
        ObjectMapper objectMapper = new ObjectMapper();
        String jsonMessage = objectMapper.writeValueAsString(message);

        // Set up the mock channel to deliver the message
        doAnswer(invocation -> {
            String consumerTag = invocation.getArgument(0);
            DeliverCallback deliverCallback = invocation.getArgument(2);
            deliverCallback.handle(consumerTag, new Delivery(null, null, jsonMessage.getBytes()));
            return consumerTag;
        }).when(channelMock).basicConsume(eq("RECONCILER_OUT"), eq(true), any(DeliverCallback.class), any(CancelCallback.class));

        messenger.run();
        verify(channelMock, times(1)).basicConsume(eq("RECONCILER_OUT"), anyBoolean(), any(DeliverCallback.class), any(CancelCallback.class));
        verify(channelMock, times(0)).basicPublish(anyString(), eq("PNE_OUT"), any(), any());

        verify(affectedProductIdentifier, times(0)).identifyAffectedProducts(any());
    }

//    @Test
//    public void testParseIds_ValidJsonString() {
//        Messenger messenger = new Messenger("localhost", "/", 5672, "guest", "guest", "RECONCILER_OUT", "PNE_OUT");
//        String jsonString = "{\"cveId\":\"id1\"}";
//        List<String> expectedIds = Arrays.asList("id1");
//
//        List<String> actualIds = messenger.parseIds(jsonString);
//
//        assertEquals(expectedIds, actualIds);
//    }
//
//    @Test
//    public void testParseIds_InvalidJsonString() {
//        Messenger messenger = new Messenger("localhost", "/", 5672, "guest", "guest", "RECONCILER_OUT", "PNE_OUT");
//        String jsonString = "invalidJsonString";
//
//        List<String> actualIds = messenger.parseIds(jsonString);
//
//        assertNotNull(actualIds);
//        assertTrue(actualIds.isEmpty());
//    }
}

