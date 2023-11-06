import db.DatabaseHelper;
import env.SharedEnvVars;

public class PatchFixMain {
    public static void main(String[] args) {
        SharedEnvVars.initializeEnvVars(false);
        final DatabaseHelper dbh = new DatabaseHelper(
                SharedEnvVars.getDatabaseType(),
                SharedEnvVars.getHikariUrl(),
                SharedEnvVars.getHikariUser(),
                SharedEnvVars.getHikariPassword()
        );
        new PatchFinderMain(dbh).start();
        new FixFinderMain(dbh).start();
    }
}
