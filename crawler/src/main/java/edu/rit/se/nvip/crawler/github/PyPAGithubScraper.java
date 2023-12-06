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
package edu.rit.se.nvip.crawler.github;

import edu.rit.se.nvip.db.model.RawVulnerability;
import lombok.extern.slf4j.Slf4j;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.eclipse.jgit.util.FileUtils;
import edu.rit.se.nvip.utils.GitController;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Objects;

@Slf4j
public class PyPAGithubScraper {

    private static final String pypaDir = "pypa-repo";

    public PyPAGithubScraper() {

    }

    public HashMap<String, RawVulnerability> scrapePyPAGithub() {
        // clone or update pypa/advisory-database repo
        updateGitRepo();
        // extract CVEs from YAML files in /vulns subdirectories
        HashMap<String, RawVulnerability> vulnMap = extractCVEsFromVulns();
        // delete git repo once finished
        deleteRepository();
        log.info("PyPA scraper completed.");

        return vulnMap;
    }

    private HashMap<String, RawVulnerability> extractCVEsFromVulns() {
        log.info("Extracting CVEs from /vulns dir...");
        File vulnDir = Paths.get("", pypaDir, "vulns").toFile();
        File[] directories = vulnDir.listFiles();
        HashMap<String, RawVulnerability> vulnMap = new HashMap<>();
        if (directories == null) {
            log.error("Failed to parse PyPA directories... returning.");
            return vulnMap;
        }
        // loop through each dir in /vulns
        for (File subdir : directories) {
            // parse each file in current sub dir
            if (subdir.isDirectory()) {
                File[] files = subdir.listFiles();
                if (files == null) {
                    log.warn("Failed to locate files in subdirectory: " + subdir.getName());
                    continue;
                }
                for (File file : files ) {

                    try {
                        PyPAYamlFile parsedFile = PyPAYamlFile.from(file);
                        ArrayList<String> cvesInFile = parsedFile.getCves();
                        for (String c : cvesInFile) {
                            vulnMap.put(c, (new RawVulnerability(
                                    "", c, parsedFile.getPublished(), parsedFile.getModified(), parsedFile.getDetails(), "PyPA"
                            )));
                        }
                    } catch (NullPointerException e){
                        log.warn("Unable to parse {}: {}", file.getName(), e.getMessage());
                    }

                }
            }
        }
        return vulnMap;
    }

    /**
     * Clone or pull PyPA GitHub repo to be used for extraction
     */
    private void updateGitRepo() {
        // clone / pull to this local path
        Path gitFolder = Paths.get("", pypaDir);
        // clone / pull from this remote repository
        String remotePath = "https://github.com/pypa/advisory-database/";
        GitController gitController = new GitController(gitFolder.toString(), remotePath);

        File f = new File(gitFolder.toString());
        boolean pullDir = false;

        if (!f.exists())
            f.mkdirs();

        try {
            pullDir = f.exists() && Objects.requireNonNull(f.list()).length > 1;
        } catch (Exception e) {
            log.error("ERROR: gitfolder does not exist at location {}", remotePath);
            log.error("", e);
        }

        // if already locally stored instance of repo, fetch latest

        try {
            if (pullDir) {
                if (gitController.pullRepo())
                    log.info("Pulled git repo at: " + remotePath + " to: " + gitFolder);
                else
                    log.error("Failed to pull git repo at: " + remotePath + " to: " + gitFolder);
            } else {
                if (gitController.cloneRepo())
                    log.info("Cloned git repo at: " + remotePath + " to: " + gitFolder);
                else
                    log.error("Could not clone git repo at: " + remotePath + " to: " + gitFolder);

            }
        } catch(Exception e) {
            log.error("ERROR: Failed to clone or pull PythonPA Repo");
            log.error("", e);
        }
    }

    /**
     * Deletes repository from local dir
     * Once parsing is complete
     */
    public void deleteRepository() {
        log.info("Deleting PyPA repo local instance...");
        try {
            // clone / pull to this local path
            Path gitFolder = Paths.get("", pypaDir);
            File dir = new File(gitFolder.toString());
            FileUtils.delete(dir, 1);
            log.info("PyPA Repo deleted successfully!");
        } catch (IOException e) {
            log.info(e.getMessage());
        }
    }
}
