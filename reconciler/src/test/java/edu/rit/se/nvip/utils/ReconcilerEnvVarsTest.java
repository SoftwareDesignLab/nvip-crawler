package edu.rit.se.nvip.utils;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class ReconcilerEnvVarsTest {

    @Test
    void testGetters() {
        ReconcilerEnvVars envVars = new ReconcilerEnvVars();

        assertEquals("jdbc:mysql://host.docker.internal:3306/nviptest?useSSL=false&allowPublicKeyRetrieval=true", envVars.getHikariURL());
        assertEquals("root", envVars.getHikariUser());
        assertEquals("root", envVars.getHikariPassword());
        assertEquals("SIMPLE", envVars.getFilterList());
        assertEquals("SIMPLE", envVars.getReconcilerType());
        assertEquals("SIMPLE", envVars.getProcessorList());
        assertEquals("packetstorm,tenable,oval.cisecurity,exploit-db,securityfocus,kb.cert,securitytracker,talosintelligence,gentoo,vmware,bugzilla,seclists,anquanke", envVars.getKnownSources());
        assertEquals("sk-xxxxxxxxxxxxx", envVars.getOpenAIKey());
        assertEquals("src/main/java/edu/rit/se/nvip", envVars.getNvipDataDir());
        assertEquals("characterization/", envVars.getTrainingDataDir());
        assertEquals("AttackTheater.csv,Context.csv,ImpactMethod.csv,LogicalImpact.csv,Mitigation.csv", envVars.getTrainingData());
        assertEquals("5000", envVars.getCharacterizationLimit());
        assertEquals("ML", envVars.getCharacterizationApproach());
        assertEquals("Vote", envVars.getCharacterizationMethod());
        assertEquals("mysql", envVars.getDbType());
        assertEquals("nvip_data", envVars.getDataDir());
    }
}
