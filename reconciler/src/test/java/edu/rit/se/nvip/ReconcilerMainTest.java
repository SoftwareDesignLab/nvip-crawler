package edu.rit.se.nvip;

import edu.rit.se.nvip.messenger.Messenger;
import edu.rit.se.nvip.utils.ReconcilerEnvVars;
import edu.rit.se.nvip.db.DatabaseHelper;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.mockito.Mockito.*;
import static org.junit.jupiter.api.Assertions.*;

@ExtendWith(MockitoExtension.class)
class ReconcilerMainTest {

    @Mock DatabaseHelper mockDb;
    @Mock Messenger mockMes;
    @Mock ReconcilerController mockCon;

    MockedStatic<DatabaseHelper> mockedDb;
    MockedStatic<ReconcilerEnvVars> mockedEnvVars;

    @BeforeEach
    void initMocks(){
        mockedDb = mockStatic(DatabaseHelper.class);
        mockedEnvVars = mockStatic(ReconcilerEnvVars.class);
    }

    @AfterEach
    void clearMocks(){
        mockedDb.close();
        mockedEnvVars.close();
    }

    //verifies that the main can properly get jobs and process them for the reconciler controller, this tests both rabbit and db
    @Test
    void testMainWithDb() {
        // todo fix - commenting because main is going to change upon merge
//        ReconcilerMain main = new ReconcilerMain();
//        main.setMessenger(mockMes);
//        main.setDatabaseHelper(mockDb);
//        main.setController(mockCon);
//
//        Set<String> jobs = new HashSet<>();
//        jobs.add("CVE-2023-1");
//        jobs.add("CVE-2023-2");
//        jobs.add("CVE-2023-3");
//
//        mockedDb.when(DatabaseHelper::getInstance).thenReturn(mockDb);
//        mockedEnvVars.when(ReconcilerEnvVars::getInputMode).thenReturn("db");
//        when(mockDb.testDbConnection()).thenReturn(true);
//        when(mockDb.getJobs()).thenReturn(jobs);
//        doNothing().when(mockCon).main(anySet());
//        //test for db
//        main.main();
    }

    @Test
    void testMainWithDbNoJobs() {
        // todo fix - commenting because main is going to change upon merge
//        ReconcilerMain main = new ReconcilerMain();
//        main.setMessenger(mockMes);
//        main.setDatabaseHelper(mockDb);
//        main.setController(mockCon);
//
//        mockedDb.when(DatabaseHelper::getInstance).thenReturn(mockDb);
//        mockedEnvVars.when(ReconcilerEnvVars::getInputMode).thenReturn("db");
//        when(mockDb.testDbConnection()).thenReturn(true);
//
//        when(mockDb.getJobs()).thenReturn(null);
//        main.main();
    }

    @Test
    void testMainWithRabbit() {
        ReconcilerMain main = new ReconcilerMain();
        main.setMessenger(mockMes);
        main.setDatabaseHelper(mockDb);
        main.setController(mockCon);

        Set<String> jobs = new HashSet<>();
        jobs.add("CVE-2023-1");
        jobs.add("CVE-2023-2");
        jobs.add("CVE-2023-3");
        List<String> jobsList = new ArrayList<>(jobs);

        mockedDb.when(DatabaseHelper::getInstance).thenReturn(mockDb);
        mockedEnvVars.when(ReconcilerEnvVars::getInputMode).thenReturn("rabbit");
        when(mockDb.testDbConnection()).thenReturn(true);
        try {
            when(mockMes.waitForCrawlerMessage(anyInt())).thenReturn(jobsList);
        } catch (Exception e) {
            fail("Caught Unexpected exception");
        }
        doNothing().when(mockCon).main(anySet());

        main.main();
    }

    @Test
    void testMainWithRabbitNoMessages() {
        ReconcilerMain main = new ReconcilerMain();
        main.setMessenger(mockMes);
        main.setDatabaseHelper(mockDb);
        main.setController(mockCon);

        Set<String> jobs = new HashSet<>();
        jobs.add("CVE-2023-1");
        jobs.add("CVE-2023-2");
        jobs.add("CVE-2023-3");

        mockedDb.when(DatabaseHelper::getInstance).thenReturn(mockDb);
        mockedEnvVars.when(ReconcilerEnvVars::getInputMode).thenReturn("rabbit");
        when(mockDb.testDbConnection()).thenReturn(true);

        try {
            when(mockMes.waitForCrawlerMessage(anyInt())).thenReturn(null);
        } catch (Exception e) {
            fail("Caught Unexpected exception");
        }
        main.main();
    }
}