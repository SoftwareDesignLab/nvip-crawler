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
package edu.rit.se.nvip.mitre;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import edu.rit.se.nvip.DatabaseHelper;
import edu.rit.se.nvip.model.CompositeVulnerability;
import edu.rit.se.nvip.model.MitreVulnerability;
import edu.rit.se.nvip.model.Vulnerability;
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

    private String mitreGithubUrl;
    private List<String> localPaths;
    private final String gitLocalPath = "nvip_data/mitre-cve/";
    private static DatabaseHelper dbh = DatabaseHelper.getInstance();

    public MitreCveController() {
        this.mitreGithubUrl = ReconcilerEnvVars.getMitreGithubUrl();
        //if it is the first run do them all otherwise only run the last 2 years
        if(dbh.isMitreTableEmpty()){
            List<String> list = new ArrayList<>();
            list.add("nvip_data/mitre-cve/" );
            this.localPaths = list;
        }else{
            List<String> list = new ArrayList<>();
            // Getting the year as a string
            String currentYear = LocalDate.now().format(DateTimeFormatter.ofPattern("yyyy"));
            list.add("nvip_data/mitre-cve/" + currentYear);
            list.add("nvip_data/mitre-cve/" + (Integer.parseInt(currentYear)-1));
            this.localPaths = list;
        }
    }

    public void updateMitreTables() {

        // pull mitre data
        Set<MitreVulnerability> results = this.getMitreCVEsFromGitRepo();
        logger.info("{} cves found from MITRE", results.size());

        long numReserved = results.stream().filter(v -> v.getStatus() == MitreVulnerability.MitreStatus.RESERVED).count();

        logger.info("Found {} reserved CVEs from MITRE", numReserved);

        // insert mitre data into mitredata, update status for changed ones
        Set<MitreVulnerability> newVulns = this.getNewMitreVulns(results);
        dbh.insertMitreData(newVulns);
        //get changed vulns and change their status to 1 (PUBLIC)
        Set<MitreVulnerability> changedVulns = this.getChangedMitreVulns(results);
        dbh.updateMitreData(changedVulns);
        // set nvdmitrestatus.in_mitre = 1 for any new mitre vulns
        dbh.setInNvdMitreStatus(newVulns.stream().map(v -> (Vulnerability) v).collect(Collectors.toSet()));
    }

    /**
     * Get Mitre CVEs. Checks if a local git repo exists for Mitre CVEs. If not
     * clones the remote Git repo. If a local repo exists then it pulls the latest
     * updates if any. Then it recursively loads all json files in the local repo,
     * parses them and creates a CSV file at the output path.
     */
    public Set<MitreVulnerability> getMitreCVEsFromGitRepo() {
        Set<MitreVulnerability> mitreCveMap = new HashSet<>();
        GitController gitController = new GitController(gitLocalPath, mitreGithubUrl);
        logger.info("Checking local Git CVE repo...");

        // Check if repo is already cloned, if so then just pull the repo for latest changes
        File f = new File(gitLocalPath);
        boolean pullDir = false;
        try {
            pullDir = f.exists() && (f.list().length > 1); // dir exists and there are some files in it!
        } catch (Exception e) {
            logger.error("ERROR: Directory {} does not exist", gitLocalPath);
            e.printStackTrace();
        }

        if (pullDir) {
            if (gitController.pullRepo())
                logger.info("Pulled git repo at: {} to: {}, now parsing each CVE...", mitreGithubUrl, gitLocalPath);
            else {
                logger.error("Could not pull git repo at: {} to: {}", mitreGithubUrl, gitLocalPath);
            }
        } else {
            if (gitController.cloneRepo())
                logger.info("Cloned git repo at: {} to: {}, now parsing each CVE...", mitreGithubUrl, gitLocalPath);
            else {
                logger.error("Could not clone git repo at: {} to: {}", mitreGithubUrl, gitLocalPath);
            }
        }
        for(String localPath : localPaths) {

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

    public void compareReconciledCVEsWithMitre(Set<CompositeVulnerability> reconciledVulns) {
        // Get NVD CVEs
        Set<MitreVulnerability> mitreCves = dbh.getAllMitreCVEs();

        //Run comparison by iterating raw CVEs
        int inMitre = 0;
        int notInMitre = 0;
        int publicCve = 0;
        int reservedCve = 0;


        logger.info("Comparing with NVD, this may take some time....");

        // For each composite vulnerability, iterate through Mitre vulns to see if there's a match in the CVE IDs
        // If there's a match, check status of the CVE in Mitre, otherwise mark it as not in Mitre
        Map<String, MitreVulnerability> idToVuln = new HashMap<>();
        mitreCves.forEach(v -> idToVuln.put(v.getCveId(), v));

        for (CompositeVulnerability recVuln : reconciledVulns) {
            if (idToVuln.containsKey(recVuln.getCveId())) {
                MitreVulnerability mitreVuln = idToVuln.get(recVuln.getCveId());
                switch (mitreVuln.getStatus()) {
                    case PUBLIC:
                        recVuln.setMitreVuln(mitreVuln);
                        inMitre++;
                        publicCve++;
                        break;
                    case RESERVED:
                        reservedCve++;
                        notInMitre++; //todo should this be considered not in mitre? (based on what Chris says)
                        break;
                    default: {
                        break;
                    }
                }
            }
        }

        //Print Results
        logger.info("NVD Comparison Results\n" +
                        "{} in Mitre\n" +
                        "{} not in Mitre\n" +
                        "{} Reserved by Mitre\n" +
                        "{} Public in Mitre\n",
                inMitre, notInMitre, reservedCve, publicCve);

    }

    /**
     *
     * @param newVulns this is a list of vulns from the getMitreCVEsFromGitRepo() method
     * @return
     */
    public Set<MitreVulnerability> getNewMitreVulns(Set<MitreVulnerability> newVulns){
        Set<MitreVulnerability> newMitreVulns = new HashSet<>(); //new mitre vuln list
        Set<MitreVulnerability> currMitreVulns = dbh.getAllMitreCVEs(); //all current mitre cves in db

        for (MitreVulnerability newVuln : newVulns){ //for each new mitre vuln
            //if that new vuln is not in the db
            //add it to the list
            if(!currMitreVulns.contains(newVuln)){ //if it's new
                newMitreVulns.add(newVuln);
                break;
            }

        }
        return newMitreVulns;
    }

    /**
     *
     * @param newVulns this is a list of vulns from the getMitreCVEsFromGitRepo() method
     * @return
     */
    public Set<MitreVulnerability> getChangedMitreVulns(Set<MitreVulnerability> newVulns){
        Set<MitreVulnerability> newMitreVulns = new HashSet<>(); //new mitre vuln list
        Set<MitreVulnerability> currMitreVulns = dbh.getAllMitreCVEs(); //all current mitre cves in db
        Map<String, MitreVulnerability> idToVuln = new HashMap<>();
        currMitreVulns.forEach(v -> idToVuln.put(v.getCveId(), v));

        for (MitreVulnerability newVuln : newVulns) {
            if (idToVuln.containsKey(newVuln.getCveId())) {
                if (idToVuln.get(newVuln.getCveId()).getStatus() != newVuln.getStatus()) {
                    newMitreVulns.add(newVuln);
                    break;
                }
            }
        }
        return newMitreVulns;
    }

}
