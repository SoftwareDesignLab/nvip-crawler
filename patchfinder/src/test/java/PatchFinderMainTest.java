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

import edu.rit.se.nvip.db.model.CpeGroup;
import edu.rit.se.nvip.db.repositories.ProductRepository;
import messenger.Messenger;
import org.junit.Test;
import patches.PatchFinder;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CountDownLatch;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.*;

/**
 * Unit tests for PatchFinderMain class
 *
 * @author Richard Sawh
 */
public class PatchFinderMainTest {

   //write tests for main method
   @Test
   public void testMain() {
       String[] args = new String[]{"CVE-2023-1001"};
       // Clear the patch commits
       PatchFinder.getPatchCommits().clear();

       // Create a mock DatabaseHelper
       ProductRepository prodRepoMock = mock(ProductRepository.class);
       PatchFinder.init();

       // Create a mock Map of affected products
       Map<String, CpeGroup> affectedProductsMock = new HashMap<>();

       // Configure mock DatabaseHelper to return the affected products
       when(prodRepoMock.getAffectedProducts(null)).thenReturn(affectedProductsMock);

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
                    new PatchFinderMain().start();
                } catch (Exception e) {
                    fail("Exception thrown: " + e.getMessage());
                }
                latch.countDown();
            }).start();

       // Assert that no patch commits were collected
       assertEquals(0, PatchFinder.getPatchCommits().size());
   }
}