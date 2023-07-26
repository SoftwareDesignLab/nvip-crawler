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

public class StanfordCoreNLPReconcilerTest {

    private static StanfordCoreNLP pipeline;
    private static StanfordCoreNLPReconciler reconciler;


    /*

   Not exactly complete... probably will have to switch to using a model like ApacheOpenNLPReconcilerTest

    */

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

        // Test case 5: Different descriptions, existing description satisfies reconciliation conditions
        String existingDescription5 = "Existing description with more diverse language parts.";
        String newDescription5 = "New description.";
        Set<String> existingSourceDomains5 = new HashSet<>();
        String newSourceDomain5 = "example.com";

        boolean result6 = reconciler.reconcileDescriptions(existingDescription5, newDescription5, existingSourceDomains5, newSourceDomain5);
        assertFalse(result6);
    }
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