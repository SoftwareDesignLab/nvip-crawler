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

import com.rabbitmq.client.*;
import edu.rit.se.nvip.ReconcilerController;
import edu.rit.se.nvip.db.DatabaseHelper;
import edu.rit.se.nvip.db.model.CompositeVulnerability;
import edu.rit.se.nvip.db.model.RawVulnerability;
import edu.rit.se.nvip.utils.ReconcilerEnvVars;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeoutException;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class MessengerTest {

    @Nested
    public class RunTests {

        private ByteArrayOutputStream outputStream;

        MockedStatic<DatabaseHelper> mockDbh;
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

            mockDbh = mockStatic(DatabaseHelper.class);
            DatabaseHelper mockDb = mock(DatabaseHelper.class);
            when(mockDb.testDbConnection()).thenReturn(true);
            mockDbh.when(DatabaseHelper::getInstance).thenReturn(mockDb);
        }

        @AfterEach
        void clearMocks(){
            mockDbh.close();
        }

        @Test
        void testRunNoVulnsReconciled() throws IOException, TimeoutException {
            //Mocking
            ReconcilerController mockRc = mock(ReconcilerController.class);
            when(factoryMock.newConnection()).thenReturn(mockConn);
            when(mockConn.createChannel()).thenReturn(channelMock);
            when(channelMock.queueDeclare(anyString(), anyBoolean(), anyBoolean(), anyBoolean(), any())).thenReturn(null);
            when(mockRc.reconcileCves(anySet())).thenReturn(Set.of());

            doAnswer(invocation -> {
                Object[] args = invocation.getArguments();
                DeliverCallback callback = (DeliverCallback) args[2];
                String jsonMessage = "[]";
                byte[] body = jsonMessage.getBytes();
                callback.handle("", new Delivery(null, null, body));
                return null;
            }).when(channelMock).basicConsume(anyString(), anyBoolean(), any(DeliverCallback.class), (CancelCallback) any());

            Messenger messenger = new Messenger(factoryMock, "", "", mockRc);
            messenger.run();

            verify(channelMock, times(1)).basicConsume(anyString(), anyBoolean(), any(DeliverCallback.class), (CancelCallback) any());
            verify(channelMock, times(0)).basicPublish(anyString(), anyString(), any(), any());

            verify(mockRc, times(1)).reconcileCves(any());
            verify(mockRc, times(1)).characterizeCves(any());
            verify(mockRc, times(1)).updateTimeGaps(any());
            verify(mockRc, times(1)).createRunStats(any());
        }

        @Test
        void testRunVulnsReconciled() throws IOException, TimeoutException {
            //Mocking
            ReconcilerController mockRc = mock(ReconcilerController.class);
            when(factoryMock.newConnection()).thenReturn(mockConn);
            when(mockConn.createChannel()).thenReturn(channelMock);
            when(channelMock.queueDeclare(anyString(), anyBoolean(), anyBoolean(), anyBoolean(), any())).thenReturn(null);

            doAnswer(invocation -> {
                Object[] args = invocation.getArguments();
                DeliverCallback callback = (DeliverCallback) args[2];
                String jsonMessage = "[\"CVE-1234-5678\"]";
                byte[] body = jsonMessage.getBytes();
                callback.handle("", new Delivery(null, null, body));
                return null;
            }).when(channelMock).basicConsume(anyString(), anyBoolean(), any(DeliverCallback.class), (CancelCallback) any());
            CompositeVulnerability cv = new CompositeVulnerability(new RawVulnerability(1, "CVE-1234-5678", "description1", null, null, null, ""));
            cv.setVersionId(1234);

            when(mockRc.reconcileCves(anySet())).thenReturn(Set.of(cv));

            Messenger messenger = new Messenger(factoryMock, "IN", "OUT", mockRc);
            messenger.run();

            verify(channelMock, times(1)).basicConsume(anyString(), anyBoolean(), any(DeliverCallback.class), (CancelCallback) any());
            verify(channelMock, times(1)).basicPublish(eq(""), eq("OUT"), eq(null), eq("{\"vulnVersionId\":\"1234\"}".getBytes(StandardCharsets.UTF_8)));

            verify(mockRc, times(1)).reconcileCves(any());
            verify(mockRc, times(1)).characterizeCves(any());
            verify(mockRc, times(1)).updateTimeGaps(any());
            verify(mockRc, times(1)).createRunStats(any());
        }
    }

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
        assertNull(failedToParse);
    }
}
