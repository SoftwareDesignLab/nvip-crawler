package edu.rit.se.nvip.sandbox;

import java.sql.SQLException;

public class RunMessengerMains {
    private static DatabaseSandbox dbh = DatabaseSandbox.getInstance();
    public static void main(String[] args) throws InterruptedException, SQLException {
        dbh.resetDB();
        SandboxCrawler.main();
        SandboxPNE.main();
        SandboxMessenger.main();

    }
}
