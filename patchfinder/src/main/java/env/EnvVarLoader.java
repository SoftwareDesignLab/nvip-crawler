package env;

/**
 * Copyright 2023 Rochester Institute of Technology (RIT). Developed with
 * government support under contract 70RCSA22C00000008 awarded by the United
 * States Department of Homeland Security for Cybersecurity and Infrastructure Security Agency.
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
