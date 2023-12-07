/ **
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
* /

package edu.rit.se.nvip.utils;

import org.junit.jupiter.api.Test;

import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class ReconcilerEnvVarsTest {

    //verifies you can getenv vars from the env.list file
    @Test
    void testGetters() {

        String path = Paths.get(System.getProperty("user.dir"), "src", "test", "resources", "dummyENV.list").toString();
        ReconcilerEnvVars.loadFromFile(path);
        List<String> list = new ArrayList<>();
        list.add("SIMPLE");
        String KNOWN_SOURCES = "packetstorm,tenable,oval.cisecurity,exploit-db,securityfocus,kb.cert,securitytracker,talosintelligence,gentoo,vmware,bugzilla,seclists,anquanke";
        List<String> knownSourceList = Arrays.asList(KNOWN_SOURCES.split(","));
        assertEquals("jdbc:mysql://host.docker.internal:3306/nviptest?useSSL=false&allowPublicKeyRetrieval=true", ReconcilerEnvVars.getHikariURL());
        assertEquals("root", ReconcilerEnvVars.getHikariUser());
        assertEquals("root", ReconcilerEnvVars.getHikariPassword());
        assertEquals(list, ReconcilerEnvVars.getFilterList());
        assertEquals("SIMPLE", ReconcilerEnvVars.getReconcilerType());
        assertEquals(list, ReconcilerEnvVars.getProcessorList());
        assertEquals(knownSourceList, ReconcilerEnvVars.getKnownSources());
        assertEquals("sk-xxxxxxxxxxxxx", ReconcilerEnvVars.getOpenAIKey());
        assertEquals("characterization/", ReconcilerEnvVars.getTrainingDataDir());
        assertEquals("AttackTheater.csv,Context.csv,ImpactMethod.csv,LogicalImpact.csv,Mitigation.csv", ReconcilerEnvVars.getTrainingData());
        assertEquals(5000, ReconcilerEnvVars.getCharacterizationLimit());
        assertEquals("ML", ReconcilerEnvVars.getCharacterizationApproach());
        assertEquals("Vote", ReconcilerEnvVars.getCharacterizationMethod());
        assertEquals("nvip_data", ReconcilerEnvVars.getDataDir());
    }
}
