package edu.rit.se.nvip.mitre;

import com.google.gson.JsonObject;
import org.junit.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.assertEquals;


public class MitreCveParserTest {

    //verifies that the parse cve json files method can parse a given list of jsons
    @Test
    public void parseCVEJSONFiles() {
        MitreCveParser mitreCveParser = new MitreCveParser();
        ArrayList<JsonObject> jsonList = new ArrayList<>();

        JsonObject jsonWithCveMetaData = new JsonObject();
        JsonObject cveMetadata = new JsonObject();
        cveMetadata.addProperty("cveId", "CVE-2021-1234");
        cveMetadata.addProperty("state", "Public");
        jsonWithCveMetaData.add("cveMetaData", cveMetadata);

        JsonObject jsonWithCveDataMeta = new JsonObject();
        JsonObject cveDataMeta = new JsonObject();
        cveDataMeta.addProperty("ID", "CVE-2022-5678");
        cveDataMeta.addProperty("STATE", "Reserved");
        jsonWithCveDataMeta.add("CVE_data_meta", cveDataMeta);

        jsonList.add(jsonWithCveMetaData);
        jsonList.add(jsonWithCveDataMeta);

        List<String[]> cveIDList = mitreCveParser.parseCVEJSONFiles(jsonList);

        assertEquals(2, cveIDList.size());

        String[] cveIDs1 = cveIDList.get(0);
        assertEquals(2, cveIDs1.length);
        assertEquals("CVE-2021-1234", cveIDs1[0]);
        assertEquals("Public", cveIDs1[1]);

        String[] cveIDs2 = cveIDList.get(1);
        assertEquals(2, cveIDs2.length);
        assertEquals("CVE-2022-5678", cveIDs2[0]);
        assertEquals("Reserved", cveIDs2[1]);
    }

}