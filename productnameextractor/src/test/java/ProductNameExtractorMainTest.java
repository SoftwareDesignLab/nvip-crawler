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

import static org.junit.Assert.*;
import static org.junit.platform.commons.function.Try.success;

import java.util.concurrent.*;

import env.ProductNameExtractorEnvVars;
import org.junit.Test;
import java.io.File;


public class ProductNameExtractorMainTest {


    @Test
    public void testMainTestModeWithTimeout() {
        String[] args = new String[]{"CVE-2023-1001"};

        // Create an ExecutorService with a single thread
        ExecutorService executorService = Executors.newSingleThreadExecutor();

        try {
            // Use the submit method to run the main method in a separate thread
            Future<Void> future = executorService.submit(() -> {
                ProductNameExtractorMain.main(args);
                return null;
            });

            // Wait for the main method execution to complete with the specified timeout
            future.get(120, TimeUnit.SECONDS);
        } catch (TimeoutException e) {
            // Handle timeout exception
            System.err.println("Main method execution timed out.");
            // Optionally, you can fail the test here or take any other actions.
        } catch (Exception e) {
            // Handle other exceptions, if any
            e.printStackTrace();
        }
        //assert that this file exists nvip_data\data\test_results.txt
        assertTrue(new File("nvip_data\\data\\test_results.txt").exists());
    }

    //test without devmode
    @Test
    public void testMainWithoutDev(){
        String[] args = new String[]{"CVE-2023-1001"};

        // Create an ExecutorService with a single thread
        ExecutorService executorService = Executors.newSingleThreadExecutor();
        System.setProperty("TEST_MODE", "false");

        try {
            // Use the submit method to run the main method in a separate thread
            Future<Void> future = executorService.submit(() -> {
                ProductNameExtractorMain.main(args);
                return null;
            });

            // Wait for the main method execution to complete with the specified timeout
            future.get(120, TimeUnit.SECONDS);
        } catch (TimeoutException e) {
            // Handle timeout exception
            System.err.println("Main method execution timed out.");
            // Optionally, you can fail the test here or take any other actions.
        } catch (Exception e) {
            // Handle other exceptions, if any
            e.printStackTrace();
        }
        //assert that this file exists nvip_data\data\test_results.txt
        assertTrue(new File("nvip_data\\data\\test_results.txt").exists());
    }

}
