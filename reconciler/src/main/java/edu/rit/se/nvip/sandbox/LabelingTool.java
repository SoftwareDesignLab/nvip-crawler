package edu.rit.se.nvip.sandbox;


import edu.rit.se.nvip.DatabaseHelper;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Scanner;

public class LabelingTool {
    private final Logger logger = LogManager.getLogger(getClass().getSimpleName());

    private final DatabaseHelper dbh = DatabaseHelper.getInstance();

    public void runLabelingTool() {
        System.out.println("LABELING TOOL FOR GENERIC PARSER DATA INPUT (Input from `rawdescriptions` table in DB)");

        Scanner scan = new Scanner(System.in);

        System.out.println("How many descriptions would you like to assign? (Type ALL for all desc. in `rawdescriptions` or enter num)");
        String quant = scan.next();
        System.out.println();

        if (quant.equals("ALL")) {
            quant = "*";
        }

        String stmt = "SELECT " + quant + " FROM rawdescription";
        try {
            Connection conn = dbh.getConnection();
            PreparedStatement preparedStatement = conn.prepareStatement(stmt);
            ResultSet result = preparedStatement.executeQuery();
            //Iterate through result set
            while (result.next()) {
                //Print current result's info
                System.out.println("CVE ID: ");
                System.out.println("CVE Description: ");
                System.out.println("CVE Dates: ");
                System.out.println();
                System.out.println("Is CVE Good Quality? (Enter Y or N): ");
                String quality = scan.next();
                if (quality.equals("Y")) {
                    //Add cve to new table/json/csv
                }
            }
        } catch (SQLException e) {
            System.out.println("Error with sql: " + e.getMessage());
        }
    }

    public static void main(String[] args) {
        LabelingTool lb = new LabelingTool();
        lb.runLabelingTool();
    }
}
