package edu.rit.se.nvip.sandbox;

import com.zaxxer.hikari.HikariConfig;
import edu.rit.se.nvip.DatabaseHelper;
import edu.rit.se.nvip.model.RawVulnerability;

import java.sql.*;
import java.util.*;

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

    public LinkedHashMap<RawVulnerability, Integer> getFilterDataset(String quantity, boolean excludeLabeled) {
        String query = "SELECT * FROM filterdataset";
        if (excludeLabeled) {
            query += " WHERE is_garbage < 0";
        }
        if (!quantity.equals("ALL")) {
            query += " LIMIT " + quantity;
        }

        LinkedHashMap<RawVulnerability, Integer> rawVulns = new LinkedHashMap<>();
        try (Connection conn = getConnection(); PreparedStatement pstmt = conn.prepareStatement(query)) {
            ResultSet res = pstmt.executeQuery();
            while (res.next()) {
                int id = res.getInt("raw_description_id");
                String cveId = res.getString("cve_id");
                String description = res.getString("raw_description");
                Timestamp created = res.getTimestamp("created_date");
                Timestamp published = res.getTimestamp("published_date");
                Timestamp modified = res.getTimestamp("last_modified_date");
                String url = res.getString("source_url");
                RawVulnerability rawVuln = new RawVulnerability(id, cveId, description, created, published, modified, url);
                rawVulns.put(rawVuln, res.getInt("is_garbage"));
            }

        } catch (SQLException ex) {
            System.out.println(ex.toString());
        }
        return rawVulns;
    }

    public LinkedHashMap<RawVulnerability, Integer> getFilterDataset() {
        return getFilterDataset("ALL", false);
    }

    public void clearAndInsertFilterDataset(Map<RawVulnerability, Integer> rawVulns) {
        String del = "DELETE FROM filterdataset";
        String ins = "INSERT INTO filterdataset (raw_description_id, cve_id, raw_description, created_date, published_date, last_modified_date, source_url, is_garbage) VALUES (?, ?, ?, ?, ?, ?, ?, ?)";
        try (Connection conn = getConnection(); PreparedStatement delStmt = conn.prepareStatement(del); PreparedStatement insStmt = conn.prepareStatement(ins)) {
            delStmt.executeUpdate();
            for (RawVulnerability vuln : rawVulns.keySet()) {
                insStmt.setInt(1, vuln.getId());
                insStmt.setString(2, vuln.getCveId());
                insStmt.setString(3, vuln.getDescription());
                insStmt.setTimestamp(4, vuln.getCreateDate());
                insStmt.setTimestamp(5, vuln.getPublishDate());
                insStmt.setTimestamp(6, vuln.getLastModifiedDate());
                insStmt.setString(7, vuln.getSourceUrl());
                insStmt.setInt(8, rawVulns.get(vuln));
                insStmt.addBatch();
            }
            insStmt.executeBatch();
        } catch (SQLException ex) {
            ex.printStackTrace();
        }
    }

    public void setNotGarbage(Set<RawVulnerability> rawVulns) {
        String query = "UPDATE filterdataset SET is_garbage = ? WHERE raw_description_id = ?";
        try (Connection conn = getConnection(); PreparedStatement pstmt = conn.prepareStatement(query)){
            for (RawVulnerability current: rawVulns) {
                pstmt.setInt(1, 0);
                pstmt.setInt(2, current.getId());
                pstmt.addBatch();
            }
            pstmt.executeBatch();
        } catch (SQLException e) {
            System.out.println("Error setting not garbage: " + e.getMessage());
        }
    }

    public void setGarbage(Set<RawVulnerability> rejectedRawVulns) {
        String query = "UPDATE filterdataset SET is_garbage = ? WHERE raw_description_id = ?";
        try (Connection conn = getConnection(); PreparedStatement pstmt = conn.prepareStatement(query)) {
            for (RawVulnerability vuln : rejectedRawVulns) {
                pstmt.setInt(1, 1);
                pstmt.setInt(2, vuln.getId());
                pstmt.addBatch();
            }
            pstmt.executeBatch();
        } catch (SQLException ex) {
            ex.printStackTrace();
        }
    }
}
