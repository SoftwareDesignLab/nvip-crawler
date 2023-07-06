package edu.rit.se.nvip.messager;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class MessagerTest {

    private ByteArrayOutputStream outputStream;

    @BeforeEach
    void setUp() {
        outputStream = new ByteArrayOutputStream();
        System.setOut(new PrintStream(outputStream));
    }

    @Test
    void waitForCrawlerMessageTest() throws Exception {
        Messager messager = new Messager();
        // Arrange
        String testMessage = "Test message";
        List<String> expectedMessages = new ArrayList<>();
        expectedMessages.add(testMessage);

        // Redirect System.out to capture the printed output
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        System.setOut(new PrintStream(outputStream));

        // Act
        new Thread(() -> {
            try {
                messager.sendPNEMessage(expectedMessages);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }).start();

        Thread.sleep(100); // Sleep for a short duration to allow the message to be processed
        List<String> receivedMessages = messager.waitForCrawlerMessage();

        // Assert
        assertEquals(expectedMessages, receivedMessages);
    }

    @Test
    void parseIdsTest() {
        Messager messager = new Messager();
        String jsonString = "[\"id1\", \"id2\", \"id3\"]";
        List<String> expectedIds = new ArrayList<>();
        expectedIds.add("id1");
        expectedIds.add("id2");
        expectedIds.add("id3");

        List<String> actualIds = messager.parseIds(jsonString);

        assertEquals(expectedIds, actualIds);
    }
}
