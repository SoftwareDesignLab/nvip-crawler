package env;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.FileNotFoundException;
import java.util.HashMap;
import java.util.Map;

import static env.EnvVarLoader.loadEnvVarsFromFile;

public class SharedEnvVars {
    private static final Logger logger = LogManager.getLogger(PatchFinderEnvVars.class);
    private static final String envVarPath = "env.list";

    // Default values for database environment variables
    private static String databaseType = "mysql";
    private static String hikariUrl = "jdbc:mysql://localhost:3306/nvip?useSSL=false&allowPublicKeyRetrieval=true";
    private static String hikariUser = "root";
    private static String hikariPassword = "root";

    // Default values for rabbit environment variables

    private static int rabbitPollInterval = 60;
    private static String rabbitHost = "host.docker.internal";
    private static String rabbitVHost = "/";
    private static int rabbitPort = 5672;
    private static String rabbitUsername = "guest";
    private static String rabbitPassword = "guest";
    private static String patchFinderInputQueue = "PNE_OUT_PATCH";
    private static String fixFinderInputQueue = "PNE_OUT_FIX";

    public static String getDatabaseType() { return databaseType; }
    public static String getHikariUrl() { return hikariUrl; }
    public static String getHikariUser() { return hikariUser; }
    public static String getHikariPassword() { return hikariPassword; }
    public static int getRabbitPollInterval() { return rabbitPollInterval; }
    public static String getRabbitHost() { return rabbitHost; }
    public static String getRabbitVHost() { return rabbitVHost; }
    public static int getRabbitPort() { return rabbitPort; }
    public static String getRabbitUsername() { return rabbitUsername; }
    public static String getRabbitPassword() { return rabbitPassword; }
    public static String getPatchFinderInputQueue() { return patchFinderInputQueue; }
    public static String getFixFinderInputQueue() { return fixFinderInputQueue; }

    /**
     * Loads environment variables from both env.list file and System.getenv(). If both of these fail, resorts to
     * default values defined above. Prioritizes System.getenv() first and then from file second.
     */
    public static void initializeEnvVars(boolean testMode) {
        logger.info("CURRENT PATH --> " + System.getProperty("user.dir"));
        if(testMode) logger.info("Initializing Test Environment Variables...");
        else logger.info("Initializing Environment Variables...");

        Map<String, String> fileProps = null;
        Map<String, String> systemProps = System.getenv();
        String filePath = envVarPath;
        if(testMode) filePath = "src/test/" + filePath;

        try {
            // Assumes in `nvip-crawler/patchfinder` working directory
            fileProps = loadEnvVarsFromFile(filePath);
        } catch (FileNotFoundException e){
            // If that path doesn't work, assumes we are in `nvip-crawler` directory and tries new path with `patchfinder` appended to it
            try{
                String possiblePath = "patchfinder\\" + filePath;
                fileProps = loadEnvVarsFromFile(possiblePath);
            } catch (Exception ignored) {}
        }

        // If env vars couldn't be loaded from file, pass in empty map
        if(fileProps == null) fileProps = new HashMap<>();
        fetchEnvVars(systemProps, fileProps);
    }

    /**
     * Attempts to fetch all required environment variables from props map safely, logging any
     * missing or incorrect variables.
     *
     * If environment variable is not found from System.getenv(), it will attempt to fetch it from the loaded file. If it
     * is still not found, it will resort to default value. Priority: System.getenv() <- env.list file <- default values
     *
     * @param systemProps map of environment variables from System.getenv()
     * @param fileProps map of environment variables read from file
     */
    private static void fetchEnvVars(Map<String, String> systemProps, Map<String, String> fileProps) {
        fetchHikariEnvVars(systemProps, fileProps);
        fetchRabbitEnvVars(systemProps, fileProps);
    }

    /**
     * Initialize RabbitMQ env vars
     *
     * @param systemProps map of environment variables from System.getenv()
     * @param fileProps map of environment variables read from file
     */
    private static void fetchRabbitEnvVars(Map<String, String> systemProps, Map<String, String> fileProps) {

        if(systemProps.containsKey("RABBIT_POLL_INTERVAL")) {
            rabbitPollInterval = Integer.parseInt(systemProps.get("RABBIT_POLL_INTERVAL"));
            logger.info("Setting RABBIT_POLL_INTERVAL to {} seconds", rabbitPollInterval);
        } else if (fileProps.containsKey("RABBIT_POLL_INTERVAL")) {
            rabbitPollInterval = Integer.parseInt(fileProps.get("RABBIT_POLL_INTERVAL"));
            logger.info("Setting RABBIT_POLL_INTERVAL to {} seconds", rabbitPollInterval);
        } else logger.warn("Could not fetch RABBIT_POLL_INTERVAL from env vars, defaulting to {} seconds", rabbitPollInterval);

        if(systemProps.containsKey("RABBIT_HOST")) {
            rabbitHost = systemProps.get("RABBIT_HOST");
            logger.info("Setting RABBIT_HOST to {}", rabbitHost);
        } else if (fileProps.containsKey("RABBIT_HOST")) {
            rabbitHost = fileProps.get("RABBIT_HOST");
            logger.info("Setting RABBIT_HOST to {}", rabbitHost);
        } else logger.warn("Could not fetch RABBIT_HOST from env vars, defaulting to {}", rabbitHost);

        if(systemProps.containsKey("RABBIT_VHOST")) {
            rabbitVHost = systemProps.get("RABBIT_VHOST");
            logger.info("Setting RABBIT_VHOST to {}", rabbitVHost);
        } else if (fileProps.containsKey("RABBIT_VHOST")) {
            rabbitVHost = fileProps.get("RABBIT_VHOST");
            logger.info("Setting RABBIT_VHOST to {}", rabbitVHost);
        } else logger.warn("Could not fetch RABBIT_VHOST from env vars, defaulting to {}", rabbitVHost);


        if(systemProps.containsKey("RABBIT_PORT")) {
            rabbitPort = Integer.parseInt(systemProps.get("RABBIT_PORT"));
            logger.info("Setting RABBIT_PORT to {}", rabbitPort);
        } else if (fileProps.containsKey("RABBIT_PORT")) {
            rabbitPort = Integer.parseInt(fileProps.get("RABBIT_PORT"));
            logger.info("Setting RABBIT_PORT to {}", rabbitPort);
        } else logger.warn("Could not fetch RABBIT_PORT from env vars, defaulting to {}", rabbitPort);

        if(systemProps.containsKey("RABBIT_USERNAME")) {
            rabbitUsername = systemProps.get("RABBIT_USERNAME");
            logger.info("Setting RABBIT_USERNAME to {}", rabbitUsername);
        } else if (fileProps.containsKey("RABBIT_USERNAME")) {
            rabbitUsername = fileProps.get("RABBIT_USERNAME");
            logger.info("Setting RABBIT_USERNAME to {}", rabbitUsername);
        } else logger.warn("Could not fetch RABBIT_USERNAME from env vars, defaulting to {}", rabbitUsername);

        if(systemProps.containsKey("RABBIT_PASSWORD")) {
            rabbitPassword = systemProps.get("RABBIT_PASSWORD");
            logger.info("Setting RABBIT_PASSWORD to {}", rabbitPassword);
        } else if (fileProps.containsKey("RABBIT_PASSWORD")) {
            rabbitPassword = fileProps.get("RABBIT_PASSWORD");
            logger.info("Setting RABBIT_PASSWORD to {}", rabbitPassword);
        } else logger.warn("Could not fetch RABBIT_PASSWORD from env vars, defaulting to {}", rabbitPassword);

        if(systemProps.containsKey("PF_INPUT_QUEUE")) {
            patchFinderInputQueue = systemProps.get("PF_INPUT_QUEUE");
            logger.info("Setting PF_INPUT_QUEUE to {}", patchFinderInputQueue);
        } else if (fileProps.containsKey("PF_INPUT_QUEUE")) {
            patchFinderInputQueue = fileProps.get("PF_INPUT_QUEUE");
            logger.info("Setting PF_INPUT_QUEUE to {}", patchFinderInputQueue);
        } else logger.warn("Could not fetch PF_INPUT_QUEUE from env vars, defaulting to {}", patchFinderInputQueue);

        if(systemProps.containsKey("FF_INPUT_QUEUE")) {
            fixFinderInputQueue = systemProps.get("FF_INPUT_QUEUE");
            logger.info("Setting FF_INPUT_QUEUE to {}", fixFinderInputQueue);
        } else if (fileProps.containsKey("FF_INPUT_QUEUE")) {
            fixFinderInputQueue = fileProps.get("FF_INPUT_QUEUE");
            logger.info("Setting FF_INPUT_QUEUE to {}", fixFinderInputQueue);
        } else logger.warn("Could not fetch FF_INPUT_QUEUE from env vars, defaulting to {}", fixFinderInputQueue);
    }

    /**
     * Initialize database env vars
     *
     * @param systemProps map of environment variables from System.getenv()
     * @param fileProps map of environment variables read from file
     */
    private static void fetchHikariEnvVars(Map<String, String> systemProps, Map<String, String> fileProps) {

        if(systemProps.containsKey("DB_TYPE")) {
            databaseType = systemProps.get("DB_TYPE");
            logger.info("Setting DB_TYPE to {}", databaseType);
        } else if (fileProps.containsKey("DB_TYPE")) {
            databaseType = fileProps.get("DB_TYPE");
            logger.info("Setting DB_TYPE to {}", databaseType);
        } else logger.warn("Could not fetch DB_TYPE from env vars, defaulting to {}", databaseType);

        if(systemProps.containsKey("HIKARI_URL")) {
            hikariUrl = systemProps.get("HIKARI_URL");
            logger.info("Setting HIKARI_URL to {}", hikariUrl);
        } else if (fileProps.containsKey("HIKARI_URL")) {
            hikariUrl = fileProps.get("HIKARI_URL");
            logger.info("Setting HIKARI_URL to {}", hikariUrl);
        } else logger.warn("Could not fetch HIKARI_URL from env vars, defaulting to {}", hikariUrl);

        if(systemProps.containsKey("HIKARI_USER")) {
            hikariUser = systemProps.get("HIKARI_USER");
            logger.info("Setting HIKARI_USER to {}", hikariUser);
        } else if (fileProps.containsKey("HIKARI_USER")) {
            hikariUser = fileProps.get("HIKARI_USER");
            logger.info("Setting HIKARI_USER to {}", hikariUser);
        } else logger.warn("Could not fetch HIKARI_USER from env vars, defaulting to {}", hikariUser);

        if(systemProps.containsKey("HIKARI_PASSWORD")) {
            hikariPassword = systemProps.get("HIKARI_PASSWORD");
            logger.info("Setting HIKARI_PASSWORD to {}", hikariPassword);
        } else if (fileProps.containsKey("HIKARI_PASSWORD")) {
            hikariPassword = fileProps.get("HIKARI_PASSWORD");
            logger.info("Setting HIKARI_PASSWORD to {}", hikariPassword);
        } else logger.warn("Could not fetch HIKARI_PASSWORD from env vars, defaulting to {}", hikariPassword);

    }
}
