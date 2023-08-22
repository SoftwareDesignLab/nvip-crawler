package edu.rit.se.nvip;

import edu.rit.se.nvip.messenger.Messenger;
import edu.rit.se.nvip.utils.ReconcilerEnvVars;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class ReconcilerMainTest {

    @Test
    void mainTest() throws Exception {
        ReconcilerMain main = new ReconcilerMain();
        MockedStatic<DatabaseHelper> mockedDb = mockStatic(DatabaseHelper.class);
        MockedStatic<ReconcilerEnvVars> mockedEnvVars = mockStatic(ReconcilerEnvVars.class);
        DatabaseHelper mockDb = mock(DatabaseHelper.class);
        Messenger mockMes = mock(Messenger.class);
        ReconcilerController mockCon = mock(ReconcilerController.class);
        main.setMessenger(mockMes);
        main.setDatabaseHelper(mockDb);
        main.setController(mockCon);
        Set<String> jobs = new HashSet<>();
        jobs.add("CVE-2023-1");
        jobs.add("CVE-2023-2");
        jobs.add("CVE-2023-3");
        List<String> jobsList = new ArrayList<>(jobs);
        mockedDb.when(DatabaseHelper::getInstance).thenReturn(mockDb);
        mockedEnvVars.when(ReconcilerEnvVars::getInputMode).thenReturn("db");
        when(mockDb.testDbConnection()).thenReturn(true);
        when(mockDb.getJobs()).thenReturn(jobs);
        when(mockMes.waitForCrawlerMessage(anyInt())).thenReturn(jobsList);
        doNothing().when(mockCon).main(anySet());
        //test for db
        main.main();

        //testing null
        when(mockDb.getJobs()).thenReturn(null);
        main.main();
        //test for rabbit
        mockedEnvVars.when(ReconcilerEnvVars::getInputMode).thenReturn("rabbit");
        main.main();

        when(mockMes.waitForCrawlerMessage(anyInt())).thenReturn(null);
        //testing null
        main.main();

        mockedEnvVars.close();
        mockedDb.close();
    }
}