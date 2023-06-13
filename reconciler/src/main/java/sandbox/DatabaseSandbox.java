package sandbox;

import com.zaxxer.hikari.HikariConfig;
import db.DatabaseHelper;
import model.RawVulnerability;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class DatabaseSandbox extends DatabaseHelper {

    private static DatabaseSandbox databaseSandbox;

    private DatabaseSandbox(HikariConfig config) {
        super(config);
    }

    public static synchronized DatabaseSandbox getInstance() {
        if (databaseSandbox == null) {
            HikariConfig config = createHikariConfigFromEnvironment();
            databaseSandbox = new DatabaseSandbox(config);
        }
        return databaseSandbox;
    }

    public static synchronized DatabaseSandbox getInstance(String url, String username, String password)  {
        if (databaseSandbox == null) {
            HikariConfig config = createHikariConfigFromArgs(url, username, password);
            databaseSandbox = new DatabaseSandbox(config);
        }
        return databaseSandbox;
    }



    /**
     * just for some informal sandbox testing, look away
     * @param rawVulns
     */
    public void insertForTest(List<RawVulnerability> rawVulns) {
        String query = "INSERT INTO rawdescription (cve_id, raw_description, created_date, published_date, last_modified_date, source_url) VALUES (?, ?, ?, ?, ?, ?)";
        String query2 = "INSERT INTO cvejobtrack (cve_id) VALUES (?)";
        Set<String> jobbedCves = new HashSet<>();
        try (Connection conn = getConnection(); PreparedStatement pstmt = conn.prepareStatement(query); PreparedStatement pstmt2 = conn.prepareStatement(query2);
             PreparedStatement delete1 = conn.prepareStatement("DELETE FROM cvejobtrack"); PreparedStatement delete2 = conn.prepareStatement("DELETE FROM rawdescription")) {
            delete1.executeUpdate();
            delete2.executeUpdate();

            for (RawVulnerability vuln : rawVulns) {
                pstmt.setString(1, vuln.getCveId());
                pstmt.setString(2, vuln.getDescription());
                pstmt.setTimestamp(3, vuln.getCreateDate());
                pstmt.setTimestamp(4, vuln.getPublishDate());
                pstmt.setTimestamp(5, vuln.getLastModifiedDate());
                pstmt.setString(6, vuln.getSourceUrl());
                pstmt.addBatch();

                if (!jobbedCves.contains(vuln.getCveId())) {
                    pstmt2.setString(1, vuln.getCveId());
                    pstmt2.addBatch();
                    jobbedCves.add(vuln.getCveId());
                }
            }
            pstmt.executeBatch();
            pstmt2.executeUpdate();

        } catch (SQLException ex) {
            System.out.println(ex.toString());
        }
    }

    public void insertRawVuln(RawVulnerability vuln) {
        if (vuln ==  null) {
            return;
        }
        String query = "INSERT INTO rawdescription (raw_description, created_date, published_date, last_modified_date, source_url, cve_id) VALUES (?, ?, ?, ?, ?, ?)";


        try (Connection conn = getConnection(); PreparedStatement pstmt = conn.prepareStatement(query)) {
            pstmt.setString(1, vuln.getDescription());
            pstmt.setTimestamp(2, vuln.getCreateDate());
            pstmt.setTimestamp(3, vuln.getPublishDate());
            pstmt.setTimestamp(4, vuln.getLastModifiedDate());
            pstmt.setString(5, vuln.getSourceUrl());
            pstmt.setString(6, vuln.getCveId());
            pstmt.executeUpdate();
        } catch (SQLException ex) {
            System.out.println(ex.toString());
        }
    }
}
