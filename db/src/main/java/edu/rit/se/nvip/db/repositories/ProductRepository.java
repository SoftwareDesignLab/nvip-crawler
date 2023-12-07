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

import edu.rit.se.nvip.db.model.AffectedProduct;
import edu.rit.se.nvip.db.model.CpeCollection;
import edu.rit.se.nvip.db.model.CpeEntry;
import edu.rit.se.nvip.db.model.CpeGroup;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import javax.sql.DataSource;
import java.sql.*;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Slf4j
@RequiredArgsConstructor
public class ProductRepository {

    public static final Pattern CPE_PATTERN = Pattern.compile("cpe:2\\.3:[aho\\*\\-]:([^:]*):([^:]*):([^:]*):.*");

    private final DataSource dataSource;

    /**
     * Insert affected products into the database. First deletes existing data
     * in the database for the affected products in the list, then inserts the new data.
     *
     * @param cpeCollection list of affected products to be inserted
     */
    public void insertAffectedProductsToDB(CpeCollection cpeCollection) {
        log.info("Inserting Affected Products to DB!");
        // insert into cpeset table
        int cpeSetId = insertCpeSet(cpeCollection.getCve().getCveId());
        cpeCollection.setCpeSetId(cpeSetId);
        // insert into affectedproduct table
        insertAffectedProducts(cpeCollection);
        // update the cpeset fk in vulnversion
        updateVulnVersion(cpeCollection.getCve().getVersionId(), cpeSetId);
    }



    private final String insertCpeSet = "INSERT INTO cpeset (cve_id, created_date) VALUES (?, NOW())";

    private int insertCpeSet(String cveId) {
        int setId = -1;
        try (Connection conn = dataSource.getConnection(); PreparedStatement pstmt = conn.prepareStatement(insertCpeSet, Statement.RETURN_GENERATED_KEYS)) {
            pstmt.setString(1, cveId);
            pstmt.executeUpdate();
            ResultSet rs = pstmt.getGeneratedKeys();
            if (rs.next()) {
                setId = rs.getInt(1);
            }
        } catch (SQLException e) {
            log.error("Error while inserting into cpeset.\n{}", e);
        }
        return setId;
    }

    private final String insertAffectedProductSql = "INSERT INTO affectedproduct (cve_id, cpe, product_name, version, vendor, purl, swid_tag, cpe_set_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?);";


    /**
     * Updates the affected product table with a list of affected products.
     *
     * @param affectedProducts list of affected products
     */
    public void insertAffectedProducts(CpeCollection affectedProducts) {
        log.info("Inserting {} affected products...", affectedProducts.getCpes().size());

        // CPE 2.3 Regex
        // Regex101: https://regex101.com/r/9uaTQb/1
        final Pattern cpePattern = Pattern.compile("cpe:2\\.3:[aho\\*\\-]:([^:]*):([^:]*):([^:]*):.*");

        int count = 0;
        try (Connection conn = dataSource.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(insertAffectedProductSql);) {
            for (AffectedProduct affectedProduct : affectedProducts.getCpes()) {
                try {
                    // Validate and extract CPE data
                    final String cpe = affectedProduct.getCpe();
                    final Matcher m = cpePattern.matcher(cpe);
                    if(!m.find()){
                        log.warn("CPE in invalid format {}", cpe);
                        continue;
                    }

                    pstmt.setString(1, affectedProduct.getCveId());
                    pstmt.setString(2, affectedProduct.getCpe());
                    pstmt.setString(3, affectedProduct.getProductName());
                    pstmt.setString(4, affectedProduct.getVersion());
                    pstmt.setString(5, affectedProduct.getVendor());
                    pstmt.setString(6, affectedProduct.getPURL());
                    pstmt.setString(7, affectedProduct.getSWID());
                    pstmt.setInt(8, affectedProducts.getCpeSetId());

                    count += pstmt.executeUpdate();

                } catch (Exception e) {
                    log.error("Could not add affected release for Cve: {} Related Cpe: {}, Error: {}",
                            affectedProduct.getCveId(), affectedProduct.getCpe(), e.toString());
                }
            }
        } catch (SQLException e) {
            log.error(e.toString());
        }
        log.info("Done. Inserted {} affected products into the database!", count);
    }


    private final String deleteAffectedProductSql = "DELETE FROM affectedproduct where cve_id = ?;";

    /**
     * Deletes affected products for given CVEs.
     *
     * @param affectedProducts list of affected products to delete
     */
    public void deleteAffectedProducts(List<AffectedProduct> affectedProducts) {
        log.info("Deleting existing affected products in database for {} items..", affectedProducts.size());
        try (Connection conn = dataSource.getConnection();
             Statement stmt = conn.createStatement();
             PreparedStatement pstmt = conn.prepareStatement(deleteAffectedProductSql);) {
            for (AffectedProduct affectedProduct : affectedProducts) {
                pstmt.setString(1, affectedProduct.getCveId());
                pstmt.executeUpdate();
            }
        } catch (SQLException e) {
            log.error(e.toString());
        }
        log.info("Done. Deleted existing affected products in database!");
    }

    private final String updateVulnVersion = "UPDATE vulnerabilityversion SET cpe_set_id = ? WHERE vuln_version_id = ?";
    public void updateVulnVersion(int vulnVersionId, int cpeSetId) {
        log.info("Updating the cpeset fk in vulnerabilityversion");
        try (Connection conn = dataSource.getConnection(); PreparedStatement pstmt = conn.prepareStatement(updateVulnVersion)) {
            pstmt.setInt(1, cpeSetId);
            pstmt.setInt(2, vulnVersionId);
            pstmt.executeUpdate();
        } catch (SQLException e) {
            log.error(e.toString());
        }
    }




    private final String selectAffectedProductsSql = "SELECT cve_id, cpe FROM affectedproduct ORDER BY cve_id DESC, version ASC;";
    private final String selectAffectedProductsByIdsSql = "SELECT ap.cve_id, ap.cpe FROM affectedproduct AS ap " +
            "JOIN cpeset AS cs ON cs.cpe_set_id = ap.cpe_set_id " +
            "JOIN vulnerabilityversion AS vv ON vv.cpe_set_id = cs.cpe_set_id " +
            "WHERE vv.vuln_version_id = ? ORDER BY cve_id DESC, version ASC;";

    /**
     * Collects a map of CPEs with their correlated CVE and Vuln ID used for
     * collecting patches given a list of CVE ids.
     *
     * @param vulnVersionId CVE version to get affected products for
     * @return a map of affected products
     */
    public Map<String, CpeGroup> getAffectedProducts(int vulnVersionId) {
        Map<String, CpeGroup> affectedProducts = new HashMap<>();
        // Prepare statement
        try (Connection conn = dataSource.getConnection();
             PreparedStatement getAll = conn.prepareStatement(selectAffectedProductsSql);
             PreparedStatement getById = conn.prepareStatement(selectAffectedProductsByIdsSql)
        ) {
            // Execute correct statement and get result set
            ResultSet res = null;
            if(vulnVersionId == -1) {
                res = getAll.executeQuery();
                parseAffectedProducts(affectedProducts, res);
            }
            else {
                getById.setInt(1, vulnVersionId);
                res = getById.executeQuery();
                parseAffectedProducts(affectedProducts, res);
            }

        } catch (Exception e) {
            log.error("ERROR: Failed to generate affected products map: {}", e.toString());
        }

        return affectedProducts;
    }



    /**
     * Parses affected product data from the ResultSet into CpeGroup objects in the affectedProducts map.
     *
     * @param affectedProducts output map of CVE ids -> products
     * @param res result set from database query
     * @throws SQLException if a SQL error occurs
     */
    private void parseAffectedProducts(Map<String, CpeGroup> affectedProducts, ResultSet res) throws SQLException {
        // Parse results
        while (res.next()) {
            // Extract cveId and cpe from result
            final String cveId = res.getString("cve_id");
            final String cpe = res.getString("cpe");

            // Extract product name and version from cpe
            final Matcher m = CPE_PATTERN.matcher(cpe);
            if(!m.find()) {
                log.warn("Invalid cpe '{}' could not be parsed, skipping product", cpe);
                continue;
            }
            final String vendor = m.group(1);
            final String name = m.group(2);
            final String version = m.group(3);
            final CpeEntry entry = new CpeEntry(name, version, cpe);

            // If we already have this cveId stored, add specific version
            if (affectedProducts.containsKey(cveId)) {
                affectedProducts.get(cveId).addVersion(entry);
            } else {
                final CpeGroup group = new CpeGroup(vendor, name);
                group.addVersion(entry);
                affectedProducts.put(cveId, group);
            }
        }
    }



}
