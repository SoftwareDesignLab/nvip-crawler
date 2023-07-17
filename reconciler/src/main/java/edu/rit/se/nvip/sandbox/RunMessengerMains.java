package edu.rit.se.nvip.sandbox;

import java.sql.SQLException;

public class RunMessengerMains {
    private static DatabaseSandbox dbh = DatabaseSandbox.getInstance();
    public static void main(String[] args) throws Exception {
        dbh.resetDB(); //removes any raw vulns from previous runs
        SandboxCrawler.main(); //starts the crawler main
        SandboxPNE.main(); //starts the PNE main
        SandboxMessenger.main(); //starts the reconciler main

    }
}
