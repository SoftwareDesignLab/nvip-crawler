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