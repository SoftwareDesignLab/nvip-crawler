package edu.rit.se.nvip.reconciler;
import edu.stanford.nlp.pipeline.CoreDocument;
import edu.stanford.nlp.pipeline.StanfordCoreNLP;
import edu.stanford.nlp.util.PropertiesUtils;
import org.junit.BeforeClass;
import org.junit.Test;

import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

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
    public void testDocLangParts() {
        String text = "This is a test sentence.";
        CoreDocument doc = new CoreDocument(text);

        pipeline.annotate(doc);

        Map<String, Integer> expectedCounts = new HashMap<>();
        expectedCounts.put("DT", 1);
        expectedCounts.put("VBZ", 1);
        expectedCounts.put("DT", 1);
        expectedCounts.put("NN", 1);

        Map<String, Integer> resultCounts = reconciler.docLangParts(doc);

        assertNotNull(resultCounts);
        assertEquals(expectedCounts, resultCounts);
    }
}