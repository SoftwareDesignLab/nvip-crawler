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

import edu.rit.se.nvip.db.model.CompositeVulnerability;
import edu.rit.se.nvip.db.model.SSVC;
import edu.rit.se.nvip.db.model.VdoCharacteristic;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import javax.sql.DataSource;
import java.sql.*;
import java.util.Set;



@Slf4j
@RequiredArgsConstructor
public class CharacterizationRepository {

    private final DataSource dataSource;

    public int insertVdoCvssBatch(Set<CompositeVulnerability> vulns) {
        for (CompositeVulnerability vuln : vulns) {
            if (!vuln.isRecharacterized() || vuln.getVdoCharacteristics() == null) {
                continue;
            }
            insertVdoSetAndCvss(vuln);
        }
        return 1;
    }

    private static final String INSERT_VDO_SET = "INSERT INTO vdoset (cve_id, cvss_base_score, created_date) VALUES (?, ?, NOW())";
    private static final String INSERT_VDO_CHARACTERISTIC = "INSERT INTO vdocharacteristic (cve_id, vdo_label, vdo_noun_group, vdo_confidence, vdo_set_id, created_date) VALUES (?, ?, ?, ?, ?, NOW())";
    private static final String UPDATE_VV_VDO_SET = "UPDATE vulnerabilityversion SET vdo_set_id = ? WHERE vuln_version_id = ?";


    private void insertVdoSetAndCvss(CompositeVulnerability vuln) {
        try (Connection conn = dataSource.getConnection();
             PreparedStatement setStatement = conn.prepareStatement(INSERT_VDO_SET, Statement.RETURN_GENERATED_KEYS);
             PreparedStatement rowStatement = conn.prepareStatement(INSERT_VDO_CHARACTERISTIC);
             PreparedStatement vvStatement = conn.prepareStatement(UPDATE_VV_VDO_SET);) {
            // these tables should be updated atomically
            conn.setAutoCommit(false);
            // insert new vdoset
            setStatement.setString(1, vuln.getCveId());
            setStatement.setDouble(2, vuln.getCvssScoreInfo().getBaseScore());
            setStatement.executeUpdate();
            // get set id
            ResultSet rs = setStatement.getGeneratedKeys();
            int setId = -1;
            if (rs.next()) {
                setId = rs.getInt(1);
            }
            // insert vdocharacteristic rows with set id
            for (VdoCharacteristic vdo : vuln.getVdoCharacteristics()) {
                populateVDOInsert(rowStatement, vdo, setId);
                rowStatement.addBatch();
            }
            rowStatement.executeBatch();
            // put set id in vulnerabilityversion row
            vvStatement.setInt(1, setId);
            vvStatement.setInt(2, vuln.getVersionId());
            vvStatement.executeUpdate();

            conn.commit();
        } catch (SQLException ex) {
            log.error("Error while inserting vdo set and labels.\n{}", ex);
        }
    }


    private void populateVDOInsert(PreparedStatement pstmt, VdoCharacteristic vdo, int setId) throws SQLException {
        pstmt.setString(1, vdo.getCveId());
        pstmt.setString(2, vdo.getVdoLabel().vdoLabelForUI); // yes, they expect the string not the id
        pstmt.setString(3, vdo.getVdoNounGroup().vdoNameForUI); // yes, string not id
        pstmt.setDouble(4, vdo.getVdoConfidence());
        pstmt.setInt(5, setId);
    }

    private static final String EXPLOIT_EXISTS = "SELECT id FROM exploit WHERE cve_id = ?";


    public boolean exploitExists(String cveId) {
        try (Connection conn = dataSource.getConnection(); PreparedStatement pstmt = conn.prepareStatement(EXPLOIT_EXISTS)) {
            pstmt.setString(1, cveId);
            return pstmt.execute();
        } catch (SQLException ex) {
            log.error("Error while fetching exploit data.\n{}", ex);
            return false;
        }
    }

    private static final String INSERT_SSVC = "INSERT INTO ssvc (cve_id, automatable, exploit_status, technical_impact) VALUES (?, ?, ?, ?)";
    public void insertSSVCSet(Set<CompositeVulnerability> vulns) {
        String deleteOldSSVC = "DELETE FROM ssvc WHERE cve_id = ?";
        try (Connection conn = dataSource.getConnection(); PreparedStatement pstmt = conn.prepareStatement(INSERT_SSVC);
             PreparedStatement deleteStmt = conn.prepareStatement(deleteOldSSVC)) {
            conn.setAutoCommit(false);
            for (CompositeVulnerability vuln : vulns) {
                // Get SSVC data
                final SSVC ssvc = vuln.getSSVC();
                // Skip vulns w/o data
                if (!vuln.isRecharacterized() || ssvc == null) continue;
                // proceed with ssvc delete/insert
                deleteStmt.setString(1, vuln.getCveId());
                deleteStmt.executeUpdate();
                // Insert data into statement
                pstmt.setString(1, vuln.getCveId());
                pstmt.setBoolean(2, ssvc.isAutomatable());
                pstmt.setString(3, ssvc.getExploitStatus());
                pstmt.setBoolean(4, ssvc.getTechnicalImpact());
                pstmt.addBatch();
            }

            // Execute batch of statements
            pstmt.executeBatch();
            conn.commit();
        } catch (SQLException ex) {
            log.error("Error while inserting SSVC characteristics.\n{}", ex);
        }
    }
}
