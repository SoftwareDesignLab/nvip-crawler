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

package edu.rit.se.nvip.nvd;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class NvdCveParserTest {

    private final NvdCveParser parser = new NvdCveParser();

    /**
     * tests that we can parse CVEs and get their reference
     */
    @Test
    public void testParseCVEs() {
        // Create a sample JSON array for testing
        JsonArray jsonList = new JsonArray();

        // Create a sample JSON object representing a CVE entry
        JsonObject cveObject = new JsonObject();
        JsonObject cveData = new JsonObject();
        cveData.addProperty("id", "CVE-2023-1234");
        cveData.addProperty("published", "2023-06-27");
        cveData.addProperty("lastModified", "2023-06-27");
        JsonArray descriptions = new JsonArray();
        JsonObject description = new JsonObject();
        description.addProperty("value", "Sample CVE description");
        descriptions.add(description);
        cveData.add("descriptions", descriptions);
        JsonObject metrics = new JsonObject();
        JsonObject cvssMetrics = new JsonObject();
        cvssMetrics.addProperty("impactScore", "10");
        cvssMetrics.addProperty("exploitabilityScore", "8");
        JsonObject cvssData = new JsonObject();
        cvssData.addProperty("baseScore", "9.8");
        cvssData.addProperty("baseSeverity", "Critical");
        cvssMetrics.add("cvssData", cvssData);
        JsonArray cvssMetricV31 = new JsonArray();
        cvssMetricV31.add(cvssMetrics);
        metrics.add("cvssMetricV31", cvssMetricV31);
        cveData.add("metrics", metrics);
        JsonArray weaknesses = new JsonArray();
        JsonObject weakness = new JsonObject();
        JsonArray weaknessDescriptions = new JsonArray();
        JsonObject weaknessDescription = new JsonObject();
        weaknessDescription.addProperty("value", "Weakness description");
        weaknessDescriptions.add(weaknessDescription);
        weakness.add("description", weaknessDescriptions);
        weaknesses.add(weakness);
        cveData.add("weaknesses", weaknesses);
        cveObject.add("cve", cveData);

        // Add the CVE entry to the JSON array
        jsonList.add(cveObject);

        // Create an instance of the class containing the parseCVEs method
        NvdCveParser parser = new NvdCveParser();

        // Call the parseCVEs method with the sample JSON array
        List<String[]> result = parser.parseCVEs(jsonList);

        // Perform assertions to validate the output
        assertEquals(1, result.size());

        String[] data = result.get(0);
        assertEquals("CVE-2023-1234", data[0]);
        assertEquals("Sample CVE description", data[1]);
        assertEquals("2023-06-27", data[2]);
        assertEquals("2023-06-27", data[3]);
        assertEquals("9.8", data[4]);
        assertEquals("Critical", data[5]);
        assertEquals("10", data[6]);
        assertEquals("8", data[7]);
        assertEquals("Weakness description", data[8]);
        assertEquals("", data[9]);
        assertEquals("", data[10]);
        assertEquals("", data[11]);
    }


    @Test
    public void testGetCveReferences() {

        // Create sample JSON data
        JsonObject json1 = new JsonObject();
        JsonArray items1 = new JsonArray();
        JsonObject jsonCVE1 = new JsonObject();
        JsonObject jsonObj1 = new JsonObject();
        JsonObject references1 = new JsonObject();
        JsonArray referenceData1 = new JsonArray();
        JsonObject reference1 = new JsonObject();
        reference1.addProperty("url", "https://example.com/cve-1");
        referenceData1.add(reference1);
        references1.add("reference_data", referenceData1);
        jsonObj1.add("references", references1);
        jsonCVE1.add("cve", jsonObj1);
        items1.add(jsonCVE1);
        json1.add("CVE_Items", items1);

        JsonObject json2 = new JsonObject();
        JsonArray items2 = new JsonArray();
        JsonObject jsonCVE2 = new JsonObject();
        JsonObject jsonObj2 = new JsonObject();
        JsonObject references2 = new JsonObject();
        JsonArray referenceData2 = new JsonArray();
        JsonObject reference2 = new JsonObject();
        reference2.addProperty("url", "https://example.com/cve-2");
        referenceData2.add(reference2);
        references2.add("reference_data", referenceData2);
        jsonObj2.add("references", references2);
        jsonCVE2.add("cve", jsonObj2);
        items2.add(jsonCVE2);
        json2.add("CVE_Items", items2);

        ArrayList<JsonObject> jsonList = new ArrayList<>();
        jsonList.add(json1);
        jsonList.add(json2);

        // Invoke the method to get CVE references
        Map<String, Integer> cveReferences = parser.getCveReferences(jsonList);

        // Verify the result
        assertEquals(2, cveReferences.size());
        assertTrue(cveReferences.containsKey("https://example.com/cve-1"));
        assertTrue(cveReferences.containsKey("https://example.com/cve-2"));
        assertEquals(0, cveReferences.get("https://example.com/cve-1"));
        assertEquals(0, cveReferences.get("https://example.com/cve-2"));

    }

}