package edu.rit.se.nvip.db.repositories;

import edu.rit.se.nvip.db.model.AffectedProduct;
import edu.rit.se.nvip.db.model.CpeCollection;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import javax.sql.DataSource;
import java.sql.*;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Slf4j
@RequiredArgsConstructor
public class ProductRepository {

    private final DataSource dataSource;

    /**
     * Insert affected products into the database. First deletes existing data
     * in the database for the affected products in the list, then inserts the new data.
     *
     * @param cpeCollections list of affected products to be inserted
     */
    public void insertAffectedProductsToDB(List<CpeCollection> cpeCollections) {
        log.info("Inserting Affected Products to DB!");
        for (CpeCollection cpes : cpeCollections) {
            // insert into cpeset table
            int cpeSetId = insertCpeSet(cpes.getCve().getCveId());
            cpes.setCpeSetId(cpeSetId);
            // insert into affectedproduct table
            insertAffectedProducts(cpes);
            // update the cpeset fk in vulnversion
            updateVulnVersion(cpes.getCve().getVersionId(), cpeSetId);
        }
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



}
