/**
* Copyright 2021 Rochester Institute of Technology (RIT). Developed with
* government support under contract 70RCSA22C00000008 awarded by the United
* States Department of Homeland Security for Cybersecurity and Infrastructure Security Agency.
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the “Software”), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in
* all copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE.
*/

package edu.rit.se.nvip;

import edu.rit.se.nvip.messenger.Messenger;
import edu.rit.se.nvip.utils.ReconcilerEnvVars;
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

//    //verifies that the main can properly get jobs and process them for the reconciler controller, this tests both rabbit and db
//    @Test
//    void testMainWithDb() {
//        ReconcilerMain main = new ReconcilerMain();
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
//
//        //test for db
//        main.main();
//
//        verify(mockCon, times(1)).main(jobs);
//    }

//    @Test
//    void testMainWithDbNoJobs() {
//        ReconcilerMain main = new ReconcilerMain();
//        main.setDatabaseHelper(mockDb);
//        main.setController(mockCon);
//
//        mockedDb.when(DatabaseHelper::getInstance).thenReturn(mockDb);
//        mockedEnvVars.when(ReconcilerEnvVars::getInputMode).thenReturn("db");
//        when(mockDb.testDbConnection()).thenReturn(true);
//
//        when(mockDb.getJobs()).thenReturn(null);
//        main.main();
//    }

//    @Test
//    void testMainWithRabbit() {
//        ReconcilerMain main = new ReconcilerMain();
//        main.setController(mockCon);
//        main.setMessenger(mockMes);
//
//        Set<String> jobs = new HashSet<>();
//        jobs.add("CVE-2023-1");
//        jobs.add("CVE-2023-2");
//        jobs.add("CVE-2023-3");
//        List<String> jobsList = new ArrayList<>(jobs);
//
//        mockedEnvVars.when(ReconcilerEnvVars::getInputMode).thenReturn("rabbit");
//
//        main.main();
//
//        verify(mockMes, times(1)).run();
//    }

//    @Test
//    void testMainWithRabbitNoMessages() {
//        ReconcilerMain main = new ReconcilerMain();
//        main.setController(mockCon);
//        main.setMessenger(mockMes);
//
//        Set<String> jobs = new HashSet<>();
//        jobs.add("CVE-2023-1");
//        jobs.add("CVE-2023-2");
//        jobs.add("CVE-2023-3");
//
//        mockedEnvVars.when(ReconcilerEnvVars::getInputMode).thenReturn("rabbit");
//
//        main.main();
//
//        verify(mockMes, times(1)).run();
//    }
}