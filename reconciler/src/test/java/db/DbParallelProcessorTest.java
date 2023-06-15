/**
 * Copyright 2023 Rochester Institute of Technology (RIT). Developed with
 * government support under contract 70RSAT19CB0000020 awarded by the United
 * States Department of Homeland Security.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
package db;

import model.CompositeVulnerability;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.invocation.Invocation;
import org.mockito.junit.MockitoJUnitRunner;

import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.*;

@RunWith(MockitoJUnitRunner.class)
public class DbParallelProcessorTest {

    @Mock
    private DatabaseHelper dbh;

    /**
     * TODO: This test is unfinished, if there's any issue with DBParallelProcess
     *  please complete this
     */
    @Test
    @Ignore
    public void executeInParallelTest() {

        try (MockedStatic<DatabaseHelper> mockStaticDB = Mockito.mockStatic(DatabaseHelper.class)) {
            mockStaticDB.when(DatabaseHelper::getInstanceForMultiThreading).thenReturn(dbh);
            when(dbh.getExistingVulnerabilities()).thenReturn(new HashMap<>());
            when(dbh.getConnectionStatus()).thenReturn("connstatus");
            //These are unnecessary stubs, but I'm leaving them here in case we need them later
//            when(dbh.updateVulnerability(any())).thenReturn(1);
//            doNothing().when(dbh).updateNvdStatus(anyInt(), anyString());
//            doNothing().when(dbh).updateMitreStatus(anyInt(), anyString());
//            doNothing().when(dbh).updateNvdTimeGap(anyInt(), anyString());
//            doNothing().when(dbh).updateMitreTimeGap(anyInt(), anyString());
//            doReturn(0).when(dbh).deleteVulnSource(anyString());
//            doReturn(true).when(dbh).insertVulnSource(anyList());
//            doNothing().when(dbh).updateVdoLabels(anyString(), anyList());
//            doReturn(0).when(dbh).deleteCvssScore(anyString());
//            doNothing().when(dbh).insertCvssScore(anyList());
//            doReturn(true).when(dbh).insertVulnerabilityUpdate(anyInt(), anyString(), anyString(), anyInt());

            doNothing().when(dbh).insertVulnerability(any());
            doReturn(true).when(dbh).insertVulnSource(anyList());
            doReturn(true).when(dbh).insertVdoCharacteristic(anyList());
            doNothing().when(dbh).insertCvssScore(any());

            when(dbh.getVulnerabilityIdList(any())).thenReturn(new ArrayList<>());

//            doReturn(true).when(dbh).insertVulnerabilityUpdate(anyInt(), anyString(), anyString(), anyInt());
            List<CompositeVulnerability> vulns = new ArrayList<>();
            for (int i = 0; i < 5000; i++) {
                vulns.add(new CompositeVulnerability(i, "source", "cve", "platform", Timestamp.valueOf("2023-01-01 10:00:00"), Timestamp.valueOf("2023-02-01 00:00:00"), "description", "domain"));
            }
            verify(dbh, times(1)).insertVulnerability(any(CompositeVulnerability.class));
            DbParallelProcessor dbpp = new DbParallelProcessor();
            dbpp.executeInParallel(vulns, 10101);
            Collection<Invocation> invocations = Mockito.mockingDetails(dbh).getInvocations();
            boolean hasShutdown = false;
            boolean hasInsert = false;
            for (Invocation inv : invocations) {
                if (inv.toString().equals("dbh.shutdown();")) {
                    hasShutdown = true;
                }
                if (inv.toString().equals("dbh.insertVulnerability(any());")) {
                    hasInsert = true;
                }
            }

            assertTrue(hasShutdown && hasInsert);
        } catch (Exception e) {e.printStackTrace(); fail();}

    }
}