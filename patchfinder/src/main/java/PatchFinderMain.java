import messenger.Messenger;
import model.CpeGroup;

import java.io.IOException;
import java.util.List;
import java.util.Map;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class PatchFinderMain {
    private final static boolean devMode = false;
    private final static Logger logger = LogManager.getLogger(PatchFinderMain.class);
    public static void main(String[] args) throws IOException, InterruptedException {
        logger.info("Starting PatchFinder...");
        // Init PatchFinder
        PatchFinder.init();

        // If dev mode, pull directly from db
        if(devMode) {
            // Fetch affectedProducts from db
            Map<String, CpeGroup> affectedProducts = PatchFinder.getDatabaseHelper().getAffectedProducts(null);
            final int affectedProductsCount = affectedProducts.values().stream().map(CpeGroup::getVersionsCount).reduce(0, Integer::sum);
            logger.info("Successfully got {} CVEs mapped to {} affected products from the database", affectedProducts.size(), affectedProductsCount);
            PatchFinder.run(affectedProducts);
        } else {
            // Start busy-wait loop
            logger.info("Starting busy-wait loop for jobs...");
            final Messenger rabbitMQ = new Messenger("localhost", "guest", "guest");
            while(true) {
                try {
                    // Wait and get jobs
                    final List<String> jobs = rabbitMQ.waitForProductNameExtractorMessage(15);

                    // If null is returned, either and error occurred or intentional program quit
                    if(jobs == null) break;

                    // Otherwise, run received jobs
                    PatchFinder.run(jobs);
                } catch (IOException e) {
                    logger.error("A fatal error occurred during job waiting: {}", e.toString());
                    break;
                }
            }
        }
    }
}
