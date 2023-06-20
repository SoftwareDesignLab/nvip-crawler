package edu.rit.se.nvip.sandbox;

import edu.rit.se.nvip.model.RawVulnerability;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.Scanner;
import java.util.Set;

public class LabelingTool {
    private static final String DB_URL = "jdbc:mysql://localhost:3306/nviptest?useSSL=false&allowPublicKeyRetrieval=true";
    private static final String DB_USER = "root";
    private static final String DB_PASS = "password";
    public void runLabelingTool() {
        System.out.println("LABELING TOOL FOR GENERIC PARSER DATA INPUT (Input from `filterdataset` table in DB)");

        Scanner scan = new Scanner(System.in);

        //Create empty rejected
        Set<RawVulnerability> rejected = new HashSet<>();

        //Create empty accepted list
        Set<RawVulnerability> accepted = new HashSet<>();

        System.out.println("How many descriptions would you like to assign? (Type ALL for all desc. in `filterdataset` or enter num)");
        String quant = scan.next();
        DatabaseSandbox dbs = DatabaseSandbox.getInstance(DB_URL, DB_USER, DB_PASS);
        LinkedHashMap<RawVulnerability, Integer> rawVulnMap = dbs.getFilterDataset(quant, true, false);
        //Iterate through result set
        for (RawVulnerability current : rawVulnMap.keySet()) {
            clearConsole();
            //Print current result's info
            System.out.println(vulnString(current));
            System.out.println("Is CVE Good Quality? Enter 'y' for yes, 'n' for no, 's' to skip, or 'q' to quit: ");
            String input = "";
            while (!input.equals("y") && !input.equals("n") && !input.equals("s") && !input.equals("q")) {
                input = scan.next();
            }
            switch (input) {
                case "y":
                    accepted.add(current);
                    break;
                case "n":
                    rejected.add(current);
                    break;
                case "s":
                    break;
                case "q":
                    String saveInput = "";
                    while (!saveInput.equals("y") && !saveInput.equals("n")) {
                        clearConsole();
                        System.out.println("Save progress? Enter y/n: ");
                        saveInput = scan.next();
                    }
                    if (saveInput.equals("y")) {
                        dbs.setNotGarbage(accepted);
                        dbs.setGarbage(rejected);
                        System.out.printf("Accepted %d and Rejected %d%n", accepted.size(), rejected.size());
                        System.exit(0);
                    }
                    break;
            }
        }
        dbs.setNotGarbage(accepted);
        dbs.setGarbage(rejected);
    }

    private static String vulnString(RawVulnerability vuln) {
        StringBuilder sb = new StringBuilder();
        sb.append(String.format("%d. %s from %s on %s\n", vuln.getId(), vuln.getCveId(), vuln.getSourceUrl(), vuln.getPublishDate()));
        sb.append(String.format("Description:\n%s", vuln.getDescription()));
        return sb.toString();
    }

    private static void clearConsole() {
        System.out.print("\033[H\033[2J"); //clears and resets the cursor to top left
        System.out.flush();
    }

    public static void main(String[] args) {
        LabelingTool lb = new LabelingTool();
        lb.runLabelingTool();
    }
}
