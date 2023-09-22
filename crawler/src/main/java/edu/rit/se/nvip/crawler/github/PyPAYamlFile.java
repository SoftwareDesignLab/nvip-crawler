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
package edu.rit.se.nvip.crawler.github;

import lombok.Data;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.nd4j.shade.yaml.snakeyaml.Yaml;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@Data
public class PyPAYamlFile {

    // PYSEC ID found at top of file
    private final String id;

    // Vuln description
    private final String details;

    // Publish date
    private final String published;

    // Last modified date
    private final String modified;

    // Affected Array of Obj
    // TODO: proper access methods and types
    //private final List<Object> affected;

    // Array of { type: String, url: String } objects
    // TODO: proper access methods
    //private final ArrayList<LinkedHashMap<String, String>> references;

    // Array of vuln aliases (CVE IDs located in here)
    private final List<String> aliases;

    private static final Logger logger = LogManager.getLogger(PyPAYamlFile.class.getSimpleName());

    public static PyPAYamlFile from(File f) {

        Map<String, Object> data;
        try {
            InputStream inputStream = Files.newInputStream(f.toPath());
            Yaml yaml = new Yaml();
            data = yaml.load(inputStream);
        } catch (IOException fe) {
            logger.error("YAML Parser I/O exception for file: " + f.getName());
            return null;
        }

        String id = data.getOrDefault("id", "").toString();
        String details = data.getOrDefault("details", "").toString();
        String modified = data.getOrDefault("modified", "").toString();
        String published = data.getOrDefault("published", "").toString();
//        List<Object> affected = (ArrayList<Object>) data.get("affected");
//        ArrayList<LinkedHashMap<String, String>> references = (ArrayList<LinkedHashMap<String, String>>) data.get("references");
        List<String> aliases = data.get("aliases") == null ? new ArrayList<>() : (ArrayList<String>) data.get("aliases");

        return new PyPAYamlFile(id, details, published, modified, aliases);
    }

    /**
     * access aliases and search for any alias that contains a CVE id
     */
    public ArrayList<String> getCves() {
        ArrayList<String> cves = new ArrayList<>();
        if (this.aliases != null) {
            for (String alias : this.aliases) {
                if (alias.contains("CVE-"))
                    cves.add(alias);
            }
        }
        return cves;
    }
}
