import messenger.Messenger;
import model.CpeGroup;

import java.io.IOException;
import java.util.List;
import java.util.Map;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Main class for the PatchFinder, drives initialization and busy-waiting for jobs
 *
 * @author Dylan Mulligan
 */
public class PatchFinderMain {
    private final static boolean devMode = false;
    private final static Logger logger = LogManager.getLogger(PatchFinderMain.class);

    /**
     * Entry point for the PatchFinder, initializes necessary classes and start listening for jobs with RabbitMQ
     * @param args
     */
    public static void main(String[] args) {
        logger.info("Starting PatchFinder...");
        // Init PatchFinder
        PatchFinder.init();

        // If dev mode, pull directly from db
        if(devMode) {
            // Fetch affectedProducts from db
            Map<String, CpeGroup> affectedProducts = PatchFinder.getDatabaseHelper().getAffectedProducts(null);
            final int affectedProductsCount = affectedProducts.values().stream().map(CpeGroup::getVersionsCount).reduce(0, Integer::sum);
            logger.info("Successfully got {} CVEs mapped to {} affected products from the database", affectedProducts.size(), affectedProductsCount);
            try {
                PatchFinder.run(affectedProducts, PatchFinderEnvVars.getCveLimit());
            } catch (IOException e) {
                logger.error("A fatal error attempting to complete jobs: {}", e.toString());
            }
        } else {
            // Start busy-wait loop
            final Messenger rabbitMQ = new Messenger(
                    PatchFinderEnvVars.getRabbitHost(), // TODO: Create PatchFinderEnvVars class and move all env var code there
                    PatchFinderEnvVars.getRabbitUsername(), // TODO: Add rabbit env vars
                    PatchFinderEnvVars.getRabbitPassword()
            );
            logger.info("Starting busy-wait loop for jobs...");
            while(true) {
                try {
                    // Wait and get jobs
                    final List<String> jobs = rabbitMQ.waitForProductNameExtractorMessage(PatchFinderEnvVars.getRabbitPollInterval());

                    // If null is returned, either and error occurred or intentional program quit
                    if(jobs == null) break;

                    // Otherwise, run received jobs
                    PatchFinder.run(jobs);
                } catch (IOException | InterruptedException e) {
                    logger.error("A fatal error occurred during job waiting: {}", e.toString());
                    break;
                }
            }
        }
    }
}
