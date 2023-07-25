package edu.rit.se.nvip.sandbox;

public class RunMessengerMains {
    private static DatabaseSandbox dbh = DatabaseSandbox.getInstance();
    public static void main(String[] args) throws Exception {
        dbh.resetDB(); //removes any raw vulns from previous runs
        SandboxCrawler.main(); //starts the crawler main
        SandboxPNE.main(); //starts the PNE main
        SandboxMessenger.main(); //starts the reconciler main

    }
}
