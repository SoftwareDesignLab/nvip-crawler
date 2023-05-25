package edu.rit.se.nvip.sandbox;

import edu.rit.se.nvip.DatabaseHelper;
import edu.rit.se.nvip.model.RawVulnerability;

import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.Scanner;
import java.util.Set;

public class LabelingTool {
    private static final String DB_URL = "jdbc:mysql://localhost:3306/nviptest?useSSL=false&allowPublicKeyRetrieval=true";
    private static final String DB_USER = "root";
    private static final String DB_PASS = "root";
    public void runLabelingTool() {
        System.out.println("LABELING TOOL FOR GENERIC PARSER DATA INPUT (Input from `filterdataset` table in DB)");

        Scanner scan = new Scanner(System.in);
        System.out.println("How many descriptions would you like to assign? (Type ALL for all desc. in `rawdescriptions` or enter num)");
        String quantity = scan.next();
        System.out.println();

        //Setup database helper
        DatabaseHelper dbh = DatabaseHelper.getInstance();

        //Create empty rejected
        Set<RawVulnerability> rejected = new HashSet<>();

        //Create empty accepted list
        LinkedList<RawVulnerability> accepted = new LinkedList<>();

        System.out.println("How many descriptions would you like to assign? (Type ALL for all desc. in `filterdataset` or enter num)");
        String quant = scan.next();
        System.out.println();
        DatabaseSandbox dbs = DatabaseSandbox.getInstance(DB_URL, DB_USER, DB_PASS);
        LinkedHashMap<RawVulnerability, Integer> rawVulnMap = dbs.getFilterDataset(quant, true);
        //Iterate through result set
        for (RawVulnerability current : rawVulnMap.keySet()) {
            //Print current result's info
            System.out.println("rawdescription ID: " + current.getId());
            System.out.println("rawdescription Description: " + current.getDescription());
            System.out.println("CVE ID: " + current.getCveId());
            System.out.println("CVE Dates: Created - " + current.getCreateDate() +
                    ", Published - " + current.getPublishDate() +
                    ", Modified - " + current.getLastModifiedDate());
            System.out.println("Source URL: " + current.getSourceUrl());
            System.out.println();
            System.out.println("Is CVE Good Quality? (Enter Y or N): ");
            String quality = scan.next();
            System.out.println();

            if (quality.equals("Y")) {
                accepted.add(current);
            } else {
                rejected.add(current);
            }
        }
        dbs.setNotGarbage(accepted);
        dbh.markGarbage(rejected);
    }

    public static void main(String[] args) {
        LabelingTool lb = new LabelingTool();
        lb.runLabelingTool();
    }
}
