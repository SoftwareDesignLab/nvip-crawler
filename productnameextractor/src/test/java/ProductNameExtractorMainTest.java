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
