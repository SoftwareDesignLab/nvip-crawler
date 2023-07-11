import db.DatabaseHelper;
import messenger.Messenger;
import model.CpeGroup;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.*;

public class PatchFinderMainTest {

   //write tests for main method
    @Test
    public void testMain() throws IOException, InterruptedException {
        String[] args = new String[]{"CVE-2023-1001"};
        //clear the patch commits
        PatchFinder.getPatchCommits().clear();
        PatchFinderMain.main(args);
        //assert that 26 patch commits were collected
        assertEquals(26, PatchFinder.getPatchCommits().size());
    }
}