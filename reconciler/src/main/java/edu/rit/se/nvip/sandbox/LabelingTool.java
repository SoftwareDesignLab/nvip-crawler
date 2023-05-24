package edu.rit.se.nvip.sandbox;


import edu.rit.se.nvip.model.RawVulnerability;
=
import java.util.LinkedList;
import java.util.Scanner;

public class LabelingTool {
    public void runLabelingTool() {
        System.out.println("LABELING TOOL FOR GENERIC PARSER DATA INPUT (Input from `rawdescriptions` table in DB)");

        Scanner scan = new Scanner(System.in);

        System.out.println("How many descriptions would you like to assign? (Type ALL for all desc. in `rawdescriptions` or enter num)");
        String quant = scan.next();
        System.out.println();
        DatabaseSandbox dbs = DatabaseSandbox.getInstance();
        LinkedList<RawVulnerability> rawVulnList = dbs.getRawDescriptions(quant);
        //Iterate through result set
        while (rawVulnList.size() != 0) {
            RawVulnerability current = rawVulnList.pop();
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
            if (quality.equals("Y")) {
                //Add cve to new table/json/csv
            }
        }
    }

    public static void main(String[] args) {
        LabelingTool lb = new LabelingTool();
        lb.runLabelingTool();
    }
}
