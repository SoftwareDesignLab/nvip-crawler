package env;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

public class EnvVarLoader {
    private static final Logger logger = LogManager.getLogger(EnvVarLoader.class);


    /**
     * Loads environment variables from file into HashMap and returns it.
     *
     * @param path path to env.list file
     * @return map of environment variables
     */
    public static Map<String, String> loadEnvVarsFromFile(String path) throws FileNotFoundException {
        Map<String, String> props = new HashMap<>();

        try {
            FileReader fileReader = new FileReader(path);
            BufferedReader reader = new BufferedReader(fileReader);

            // Go through each line
            String line = reader.readLine();
            while (line != null) {
                // If it contains an equals sign, is an environment variable
                if (line.contains("=")) {
                    int index = line.indexOf('=');
                    // Add the env var and its value
                    props.put(line.substring(0, index), line.substring(index + 1));
                }

                line = reader.readLine();
            }

        } catch(FileNotFoundException e){
            throw e;
        } catch (IOException e){
            logger.error("Reading from environment variable file failed with error {}", e.toString());
        }

        return props;

    }
}
