import db.DatabaseHelper;
import messenger.Messenger;
import model.CpeGroup;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import java.io.IOException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;


import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.*;

public class PatchFinderMainTest {

   //write tests for main method
   @Test
   public void testMain() throws IOException, InterruptedException {
       String[] args = new String[]{"CVE-2023-1001"};
       // Clear the patch commits
       PatchFinder.getPatchCommits().clear();

       // Create a mock DatabaseHelper
       DatabaseHelper databaseHelperMock = mock(DatabaseHelper.class);
       PatchFinder.init();

       // Create a mock Map of affected products
       Map<String, CpeGroup> affectedProductsMock = new HashMap<>();

       // Configure mock DatabaseHelper to return the affected products
       when(databaseHelperMock.getAffectedProducts(null)).thenReturn(affectedProductsMock);

       // Create a mock Messenger
       Messenger messengerMock = mock(Messenger.class);

       // Configure mock Messenger to return null after a 10-second delay (simulate timeout)
       when(messengerMock.waitForProductNameExtractorMessage(anyInt())).thenAnswer(invocation -> {
           Thread.sleep(10000);
           return null;
       });

       // Initialize PatchFinder with the mock Messenger
       PatchFinder.init();

       // Call the main method then timeout after 10 seconds
         CountDownLatch latch = new CountDownLatch(1);
            new Thread(() -> {
                try {
                    PatchFinderMain.main(args);
                } catch (Exception e) {
                    fail("Exception thrown: " + e.getMessage());
                }
                latch.countDown();
            }).start();

       // Assert that no patch commits were collected
       assertEquals(0, PatchFinder.getPatchCommits().size());

   }
}