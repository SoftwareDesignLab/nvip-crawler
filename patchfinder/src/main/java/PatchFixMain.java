import db.DatabaseHelper;
import env.SharedEnvVars;
import messenger.Messenger;

public class PatchFixMain {
    public static void main(String[] args) {
        SharedEnvVars.initializeEnvVars(false);

        // Init dbh
        final DatabaseHelper dbh = new DatabaseHelper(
                SharedEnvVars.getDatabaseType(),
                SharedEnvVars.getHikariUrl(),
                SharedEnvVars.getHikariUser(),
                SharedEnvVars.getHikariPassword()
        );

        // Init messenger
        final Messenger m = new Messenger(
                SharedEnvVars.getRabbitHost(),
                SharedEnvVars.getRabbitVHost(),
                SharedEnvVars.getRabbitPort(),
                SharedEnvVars.getRabbitUsername(),
                SharedEnvVars.getRabbitPassword()
        );

        // Init and start Patchfinder/Fixfinder with dbh and messenger instances
        new PatchFinderMain(dbh, m).start();
        new FixFinderMain(dbh, m).start();
    }
}
