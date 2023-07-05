package edu.rit.se.nvip.utils;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class ReconcilerEnvVarsTest {

    @Test
    void testGetters() {

        ReconcilerEnvVars.loadEnvList();
        List<String> list = new ArrayList<>();
        list.add("SIMPLE");
        assertEquals("jdbc:mysql://host.docker.internal:3306/nviptest?useSSL=false&allowPublicKeyRetrieval=true", ReconcilerEnvVars.getHikariURL());
        assertEquals("root", ReconcilerEnvVars.getHikariUser());
        assertEquals("root", ReconcilerEnvVars.getHikariPassword());
        assertEquals(list, ReconcilerEnvVars.getFilterList());
        assertEquals("SIMPLE", ReconcilerEnvVars.getReconcilerType());
        assertEquals(list, ReconcilerEnvVars.getProcessorList());
        assertEquals("packetstorm,tenable,oval.cisecurity,exploit-db,securityfocus,kb.cert,securitytracker,talosintelligence,gentoo,vmware,bugzilla,seclists,anquanke", ReconcilerEnvVars.getKnownSources());
        assertEquals("sk-xxxxxxxxxxxxx", ReconcilerEnvVars.getOpenAIKey());
        assertEquals("src/main/java/edu/rit/se/nvip", ReconcilerEnvVars.getNvipDataDir());
        assertEquals("characterization/", ReconcilerEnvVars.getTrainingDataDir());
        assertEquals("AttackTheater.csv,Context.csv,ImpactMethod.csv,LogicalImpact.csv,Mitigation.csv", ReconcilerEnvVars.getTrainingData());
        assertEquals(5000, ReconcilerEnvVars.getCharacterizationLimit());
        assertEquals("ML", ReconcilerEnvVars.getCharacterizationApproach());
        assertEquals("Vote", ReconcilerEnvVars.getCharacterizationMethod());
        assertEquals("mysql", ReconcilerEnvVars.getDbType());
        assertEquals("nvip_data", ReconcilerEnvVars.getDataDir());
    }
}
