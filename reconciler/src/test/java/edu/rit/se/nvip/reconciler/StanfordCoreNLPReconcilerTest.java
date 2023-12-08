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

package edu.rit.se.nvip.reconciler;

import edu.stanford.nlp.pipeline.CoreDocument;
import edu.stanford.nlp.pipeline.StanfordCoreNLP;
import edu.stanford.nlp.util.PropertiesUtils;
import org.junit.BeforeClass;
import org.junit.Test;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class StanfordCoreNLPReconcilerTest {

    private static StanfordCoreNLP pipeline;
    private static StanfordCoreNLPReconciler reconciler;


    @BeforeClass
    public static void setUp() {
        pipeline = new StanfordCoreNLP(PropertiesUtils.asProperties(
                "annotators", "tokenize,ssplit,pos",
                "ssplit.isOneSentence", "true",
                "tokenize.language", "en"
        ));

        reconciler = new StanfordCoreNLPReconciler();
    }
    @Test
    public void reconcileDescriptionsTest() {
        StanfordCoreNLPReconciler reconciler = new StanfordCoreNLPReconciler();

        // Test case 1: Same existing and new descriptions
        String existingDescription1 = "This is an example description.";
        String newDescription1 = "This is an example description.";
        Set<String> existingSourceDomains1 = new HashSet<>();
        String newSourceDomain1 = "example.com";

        boolean result1 = reconciler.reconcileDescriptions(existingDescription1, newDescription1, existingSourceDomains1, newSourceDomain1);
        assertFalse(result1);

        // Test case 2: Existing description is null, new description is not null
        String newDescription2 = "This is a new description.";
        Set<String> existingSourceDomains2 = new HashSet<>();
        String newSourceDomain2 = "example.com";

        boolean result2 = reconciler.reconcileDescriptions(null, newDescription2, existingSourceDomains2, newSourceDomain2);
        assertTrue(result2);


        // Test case 3: Existing source is unknown, new source is known
        String existingDescription3 = "Existing description.";
        String newDescription3 = "New description.";
        Set<String> existingSourceDomains3 = new HashSet<>();
        String newSourceDomain3 = "example.com";

        boolean result4 = reconciler.reconcileDescriptions(existingDescription3, newDescription3, existingSourceDomains3, newSourceDomain3);
        assertFalse(result4);

        // Test case 4: Different descriptions, new description satisfies reconciliation conditions
        String existingDescription4 = "Existing description.";
        String newDescription4 = "New description with more sentences and diverse language parts.";
        Set<String> existingSourceDomains4 = new HashSet<>();
        String newSourceDomain4 = "example.com";

        boolean result5 = reconciler.reconcileDescriptions(existingDescription4, newDescription4, existingSourceDomains4, newSourceDomain4);
        assertTrue(result5);

        Map<String, Integer> mockMap = mock(Map.class);
        // Test case 5: Different descriptions, existing description satisfies reconciliation conditions
        String existingDescription5 = "Existing description with more diverse language parts.";
        String newDescription5 = "New description.";
        Set<String> existingSourceDomains5 = new HashSet<>();
        String newSourceDomain5 = "example.com";
        existingSourceDomains5.add("mock");
        reconciler.setKnownCveSources(mockMap);
        when(mockMap.containsKey(anyString())).thenReturn(true);
        boolean result6 = reconciler.reconcileDescriptions(existingDescription5, newDescription5, existingSourceDomains5, newSourceDomain5);
        assertFalse(result6);
    }

    //verifies doc lang parts works correctly
    @Test
    public void docLangPartsTest() {
        String text = "Time to test a sentence!";
        CoreDocument doc = new CoreDocument(text);

        pipeline.annotate(doc);

        Map<String, Integer> expectedCounts = new HashMap<>();
        expectedCounts.put("NN", 2);
        expectedCounts.put("DT", 1);
        expectedCounts.put("VB", 1);
        expectedCounts.put(".", 1);
        expectedCounts.put("TO", 1);

        Map<String, Integer> resultCounts = reconciler.docLangParts(doc);

        assertNotNull(resultCounts);
        assertEquals(expectedCounts, resultCounts);
    }
}