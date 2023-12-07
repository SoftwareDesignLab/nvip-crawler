/ **
* Copyright 2021 Rochester Institute of Technology (RIT). Developed with
* government support under contract 70RCSA22C00000008 awarded by the United
* States Department of Homeland Security for Cybersecurity and Infrastructure Security Agency.
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the “Software”), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in
* all copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE.
* /

/**
 * Copyright 2023 Rochester Institute of Technology (RIT). Developed with
 * government support under contract 70RCSA22C00000008 awarded by the United
 * States Department of Homeland Security for Cybersecurity and Infrastructure Security Agency.for Cybersecurity and Infrastructure Security Agency.
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
package edu.rit.se.nvip.mitre;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import edu.rit.se.nvip.db.DatabaseHelper;
import edu.rit.se.nvip.db.model.CompositeVulnerability;
import edu.rit.se.nvip.db.model.MitreVulnerability;
import edu.rit.se.nvip.db.repositories.NvdMitreRepository;
import edu.rit.se.nvip.utils.GitController;
import edu.rit.se.nvip.utils.ReconcilerEnvVars;
import org.apache.commons.io.FileUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.File;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.stream.Collectors;

/**
 *
 * Pulls CVEs from the local git repo
 *
 * @author axoeec
 *
 */
public class MitreCveController {
    private static final Logger logger = LogManager.getLogger(MitreCveController.class);

    private final String mitreGithubUrl;
    private List<String> localPaths;
    private final String gitLocalPath = "nvip_data/mitre-cve/";
    private GitController gitController;
    private File f = new File(gitLocalPath);
    private static NvdMitreRepository dbRepo;

    public MitreCveController() {
        this.mitreGithubUrl = ReconcilerEnvVars.getMitreGithubUrl();
        this.gitController = new GitController(gitLocalPath, mitreGithubUrl);
    }

    public void initializeController(){
        //if it is the first run do them all otherwise only run the last 2 years
        List<String> list = new ArrayList<>();
        if(dbRepo.isMitreTableEmpty()){
            list.add("nvip_data/mitre-cve/" );
        }else{
            // Getting the year as a string
            String currentYear = LocalDate.now().format(DateTimeFormatter.ofPattern("yyyy"));
            list.add("nvip_data/mitre-cve/" + currentYear);
            list.add("nvip_data/mitre-cve/" + (Integer.parseInt(currentYear)-1));
        }
        this.localPaths = list;
    }

    public void updateMitreTables() {
        Set<MitreVulnerability> results = getMitreCVEsFromGitRepo();

        logger.info("{} cves found from MITRE", results.size());
        long numReserved = results.stream().filter(v -> v.getStatus() == MitreVulnerability.MitreStatus.RESERVED).count();
        logger.info("Found {} reserved CVEs from MITRE", numReserved);
        Set<MitreVulnerability> toBackfill = dbRepo.upsertMitreData(results);
        logger.info("{} mitre cves were new", toBackfill.size());
        dbRepo.backfillMitreTimegaps(toBackfill); // todo get the number of inserted gaps
    }

    /**
     * Get Mitre CVEs. Checks if a local git repo exists for Mitre CVEs. If not
     * clones the remote Git repo. If a local repo exists then it pulls the latest
     * updates if any. Then it recursively loads all json files in the local repo,
     * parses them and creates a CSV file at the output path.
     */
    private Set<MitreVulnerability> getMitreCVEsFromGitRepo() {
        Set<MitreVulnerability> mitreCveMap = new HashSet<>();
        logger.info("Checking local Git CVE repo...");

        boolean pullDir = false;
        try {
            pullDir = f.exists() && (f.list().length > 1); // dir exists and there are some files in it!
        } catch (Exception e) {
            logger.error("ERROR: Directory {} does not exist", gitLocalPath);
            return mitreCveMap;
        }

        if (pullDir) {
            if (gitController.pullRepo())
                logger.info("Pulled git repo at: {} to: {}, now parsing each CVE...", mitreGithubUrl, gitLocalPath);
            else {
                logger.error("Could not pull git repo at: {} to: {}", mitreGithubUrl, gitLocalPath);
                return mitreCveMap;
            }
        } else {
            if (gitController.cloneRepo())
                logger.info("Cloned git repo at: {} to: {}, now parsing each CVE...", mitreGithubUrl, gitLocalPath);
            else {
                logger.error("Could not clone git repo at: {} to: {}", mitreGithubUrl, gitLocalPath);
                return mitreCveMap;
            }
        }

        for (String localPath : localPaths) {
            logger.info("Now parsing MITRE CVEs at {} directory", localPath);
            // create json object from .json files
            ArrayList<JsonObject> list = new ArrayList<>();

            list = getJSONFilesFromGitFolder(new File(localPath), list);

            logger.info("Collected {} JSON files at {}", list.size(), localPath);
            // parse individual json objects
            MitreCveParser mitreCVEParser = new MitreCveParser();
            List<String[]> cveData = mitreCVEParser.parseCVEJSONFiles(list);
            logger.info("Parsed {} JSON files at {}", list.size(), localPath);
            // add all CVEs to a map
            for (String[] cve : cveData) {
                String cveId = cve[0];
                String status = cve[1];
                MitreVulnerability vuln = new MitreVulnerability(cveId, status);
                mitreCveMap.add(vuln);
            }
        }
        return mitreCveMap;
    }

    /**
     * Recursively get all JSON files in the <folder>
     *
     * @param folder
     * @param jsonList
     * @return
     */
    public ArrayList<JsonObject> getJSONFilesFromGitFolder(final File folder, ArrayList<JsonObject> jsonList) {
        for (final File fileEntry : folder.listFiles()) {
            if (fileEntry.isDirectory()) {
                // skip git folders
                if (!fileEntry.getName().contains(".git"))
                    getJSONFilesFromGitFolder(fileEntry, jsonList);
            } else {
                try {
                    String filename = fileEntry.getName();
                    String extension = filename.substring(filename.lastIndexOf(".") + 1);
                    if (extension.equalsIgnoreCase("json")) {
                        String sJsonContent = FileUtils.readFileToString(fileEntry);
                        JsonObject json = JsonParser.parseString(sJsonContent).getAsJsonObject();
                        jsonList.add(json);
                    }
                } catch (Exception e) {
                    logger.error("Error while getting JSON files at " + folder.getAbsolutePath() + ": " + e);

                }
            }
        }

        logger.info("Parsed " + jsonList.size() + " CVEs in " + folder);
        return jsonList;
    }

    public Set<CompositeVulnerability> compareWithMitre(Set<CompositeVulnerability> reconciledVulns) {
        Set<CompositeVulnerability> affected = dbRepo.attachMitreVulns(reconciledVulns); // returns compvulns with attached mitrevulns
        int inMitre = (int) reconciledVulns.stream().filter(CompositeVulnerability::isInMitre).count(); // comp vuln decides what "in" means
        int notInMitre = reconciledVulns.size() - inMitre;
        Set<MitreVulnerability> mitreVulns = affected.stream().map(CompositeVulnerability::getMitreVuln).collect(Collectors.toSet()); // pull out the matching nvdvulns
        Map<MitreVulnerability.MitreStatus, Integer> statusToCount = new HashMap<>();
        for (MitreVulnerability mitreVuln : mitreVulns) { // iterate through each mitre vuln and update appropriate counters. better than 4 filter streams
            MitreVulnerability.MitreStatus status = mitreVuln.getStatus();
            if (statusToCount.containsKey(status)) {
                statusToCount.put(status, statusToCount.get(status)+1);
            } else {
                statusToCount.put(status, 1);
            }
        }

        int numReserved = 0;
        int numPublic = 0;
        if(statusToCount.get(MitreVulnerability.MitreStatus.RESERVED) != null) numReserved = statusToCount.get(MitreVulnerability.MitreStatus.RESERVED);
        if(statusToCount.get(MitreVulnerability.MitreStatus.PUBLIC) != null) numPublic = statusToCount.get(MitreVulnerability.MitreStatus.PUBLIC);

        logger.info("Mitre Comparison Results\n" +
                        "{} in Mitre\n" +
                        "{} not in Mitre\n" +
                        "{} Reserved by Mitre\n" +
                        "{} Public in Mitre\n",
                inMitre, notInMitre,
                numReserved,
                numPublic
        );

        return affected;
    }

    public void setDatabaseHelper(NvdMitreRepository nvdMitreRepository){
        dbRepo = nvdMitreRepository;
    }
    public void setGitController(GitController git){ gitController = git;}
    public void setFile(File file){ f = file;}
    public void setLocalPaths(List<String> list){
        localPaths = list;
    }
}
