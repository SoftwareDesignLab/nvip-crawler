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

package edu.rit.se.nvip.db.repositories;

import edu.rit.se.nvip.db.model.CpeEntry;
import edu.rit.se.nvip.db.model.CpeGroup;
import edu.rit.se.nvip.db.model.Fix;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import javax.sql.DataSource;
import java.sql.*;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


@Slf4j
@RequiredArgsConstructor
public class PatchFixRepository {

    private final DataSource dataSource;




    private final String getExistingSourceUrlsSql = "SELECT source_url, source_url_id FROM patchsourceurl";

    /**
     * Gets a map of CVEs -> existing source urls from the database
     * @return a map of CVEs -> existing source urls
     */
    public Map<String, Integer> getExistingSourceUrls() {
        final Map<String, Integer> urls = new HashMap<>();

        try (Connection connection = dataSource.getConnection();
             PreparedStatement pstmt = connection.prepareStatement(getExistingSourceUrlsSql)) {
            ResultSet rs = pstmt.executeQuery();
            while(rs.next()) { urls.put(rs.getString(1), rs.getInt(2)); }
        } catch (Exception e) {
            log.error(e.toString());
        }

        return urls;
    }



    private final String getExistingPatchCommitsSql = "SELECT commit_sha FROM patchcommit";

    /**
     * Gets a set of existing patch commit SHAs from the database
     * @return a set of existing patch commit SHAs
     */
    public Set<String> getExistingPatchCommitShas() {
        final Set<String> urls = new HashSet<>();

        try (Connection connection = dataSource.getConnection();
             PreparedStatement pstmt = connection.prepareStatement(getExistingPatchCommitsSql)) {
            ResultSet rs = pstmt.executeQuery();
            while(rs.next()) { urls.add(rs.getString(1)); }
        } catch (Exception e) {
            log.error(e.toString());
        }

        return urls;
    }


    private final String insertPatchSourceURLSql = "INSERT INTO patchsourceurl (cve_id, source_url) VALUES (?, ?);";

    /**
     * Inserts given source URL into the patch source table
     *
     * @param existingSourceUrls map of CVE ids -> the id of the source url
     * @param cve_id CVE being processed
     * @param sourceURL source url to insert
     * @return generated primary key (or existing key)
     */
    public int insertPatchSourceURL(Map<String, Integer> existingSourceUrls, String cve_id, String sourceURL) {
        // Check if source already exists
        if(existingSourceUrls.containsKey(sourceURL)) {
            // Get and return id from map
            return existingSourceUrls.get(sourceURL);
        } else { // Otherwise, insert and return generated id
            try (Connection conn = dataSource.getConnection(); PreparedStatement pstmt = conn.prepareStatement(insertPatchSourceURLSql, Statement.RETURN_GENERATED_KEYS)) {
                pstmt.setString(1, cve_id);
                pstmt.setString(2, sourceURL);
                pstmt.executeUpdate();

                final ResultSet rs = pstmt.getGeneratedKeys();
                int generatedKey = 0;
                if (rs.next()) generatedKey = rs.getInt(1);
                else throw new SQLException("Could not retrieve key of newly created record, it may not have been inserted");

                conn.close();
                log.info("Inserted PatchURL: " + sourceURL);
                existingSourceUrls.put(sourceURL, generatedKey);
                return generatedKey;
            } catch (Exception e) {
                log.error("ERROR: Failed to insert patch source with sourceURL {} for CVE ID {}\n{}", sourceURL,
                        cve_id, e.getMessage());
                return -1;
            }
        }
    }

    private final String insertPatchCommitSql = "INSERT INTO patchcommit (source_url_id, cve_id, commit_sha, commit_date, commit_message, uni_diff, timeline, time_to_patch, lines_changed) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);";


    /**
     * Method for inserting a patch commit into the patchcommit table
     *
     * @param sourceId id of the source url
     * @param commitSha commit SHA
     * @param commitDate commit date
     * @param commitMessage commit message
     * @param uniDiff unified diff String
     * @param timeLine timeline list of String objects
     * @param timeToPatch time from CVE release -> patch release
     * @param linesChanged number of lines changed
     * @throws IllegalArgumentException if given source id is invalid (sourceId < 0)
     */
    public void insertPatchCommit(int sourceId, String cveId, String commitSha, java.util.Date commitDate, String commitMessage, String uniDiff, List<String> timeLine, String timeToPatch, int linesChanged) throws IllegalArgumentException {
        if (sourceId < 0) throw new IllegalArgumentException("Invalid source id provided, ensure id is non-negative");

        try (Connection connection = dataSource.getConnection();
             PreparedStatement pstmt = connection.prepareStatement(insertPatchCommitSql);
             PreparedStatement pstmtExistingCommit = connection.prepareStatement("SELECT commit_sha FROM patchcommit WHERE commit_sha = ? LIMIT 1");
             PreparedStatement pstmtUpdateCommit = connection.prepareStatement("UPDATE patchcommit SET commit_date = ?, commit_message = ?, uni_diff = ?, timeline = ?, time_to_patch = ?, lines_changed = ? WHERE commit_sha = ?")
        ) {
            // Check if the commit URL already exists in the database
            pstmtExistingCommit.setString(1, commitSha);
            ResultSet existingCommitResult = pstmtExistingCommit.executeQuery();

            if (existingCommitResult.next()) {
                // Existing commit found
                log.warn("Patch commit '{}' already exists in the database", commitSha);

                // Perform the appropriate action for existing entries (diff, replace, ignore)
                // Here, we are updating the existing commit with the new information
                pstmtUpdateCommit.setDate(1, new java.sql.Date(commitDate.getTime()));
                pstmtUpdateCommit.setString(2, commitMessage);// TODO: Fix data truncation error
                pstmtUpdateCommit.setString(3, uniDiff);
                pstmtUpdateCommit.setString(4, timeLine.toString());
                pstmtUpdateCommit.setString(5, timeToPatch);
                pstmtUpdateCommit.setInt(6, linesChanged);
                pstmtUpdateCommit.setString(7, commitSha);
                pstmtUpdateCommit.executeUpdate();

                log.info("Existing patch commit updated: {}", commitSha);
            } else {
                // Insert the new patch commit
                pstmt.setInt(1, sourceId);
                pstmt.setString(2, cveId);
                pstmt.setString(3, commitSha);
                pstmt.setDate(4, new java.sql.Date(commitDate.getTime()));
                pstmt.setString(5, commitMessage);
                pstmt.setString(6, uniDiff);
                pstmt.setString(7, timeLine.toString());
                pstmt.setString(8, timeToPatch);
                pstmt.setInt(9, linesChanged);
                pstmt.executeUpdate();

                log.info("New patch commit inserted: {}", commitSha);
            }
        } catch (Exception e) {
            log.error("ERROR: Failed to insert/update patch commit from source {}: {}", commitSha, e);
            throw new IllegalArgumentException(e);
        }
    }



    private final String getSpecificCveSourcesSql = "SELECT cve_id, source_url FROM nvip.rawdescription WHERE source_url != \"\" AND cve_id = ?;";

    public ArrayList<String> getSpecificCveSources(String cve_id) {
        ArrayList<String> sources = new ArrayList<>();
        try (Connection conn = dataSource.getConnection(); PreparedStatement pstmt = conn.prepareStatement(getSpecificCveSourcesSql)) {
            pstmt.setString(1, cve_id);
            ResultSet rs = pstmt.executeQuery();
            while (rs.next()) {
                sources.add(rs.getString("source_url"));
            }
        } catch (Exception e) {
            log.error("ERROR: Failed to get CVE sources for CVE ID {}\n{}", cve_id, e.getMessage());
        }
        return sources;
    }


    private final String insertFixSql = "INSERT INTO fixes (cve_id, fix_description, source_url) VALUES (?, ?, ?);";

    /**
     * Method for inserting a fix into the fixes table
     * Should also check for duplicates
     *
     * @param fix Fix object to be inserted
     *
     * @return 0 for success, 1 for error, 2 for duplicate entry
     */
    public int insertFix(Fix fix) throws SQLException {
        String cveId = fix.getCveId();
        String fixDescription = fix.getFixDescription();
        String sourceUrl = fix.getSourceUrl();

        try (Connection connection = dataSource.getConnection();
             PreparedStatement pstmt = connection.prepareStatement(insertFixSql)
        ) {
            // Insert the fix
            pstmt.setString(1, cveId);
            pstmt.setString(2, fixDescription);
            pstmt.setString(3, sourceUrl);
            pstmt.executeUpdate();
            log.info("Inserted fix for CVE ID {}", cveId);
        } catch (SQLIntegrityConstraintViolationException e) {
            // Check if error relates to duplicate entries, if so, return 2
            if(e.getMessage().startsWith("Duplicate")) return 2;
                // Otherwise, report error and return 1
            else {
                log.error("Failed to insert Fix: {}", e.toString());
                e.printStackTrace();
                return 1;
            }
        }
        // If statement execution was successful, return 0
        return 0;
    }

    /**Attempts to insert a set of fixes using the insertfix method
     * Successes are not referenced later in this method
     * @param fixes a set of fix objects to attempt to insert
     * @return the number of failed inserts and the number of existing inserts, in {failed,existing} format
     */
    public int[] insertFixes(Set<Fix> fixes) {
        int failedInserts = 0;
        int existingInserts = 0;

        for (Fix fix : fixes) {
            try {
                final int result = this.insertFix(fix);
                // Result of operation, 0 for OK, 1 for failed, 2 for already exists
                switch (result) {
                    case 1:
                        failedInserts++;
                        break;
                    case 2:
                        existingInserts++;
                        break;
                    default:
                        break;
                }
            }
            catch (SQLException e) {
                log.error("Failed to insert fix {}: {}", fix, e.toString());
            }
        }

        return new int[] {failedInserts, existingInserts};
    }
}
