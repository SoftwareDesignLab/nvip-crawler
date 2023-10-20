package edu.rit.se.nvip.reconciler;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class ReconcilerFactoryTest {
    private final Logger log = LogManager.getLogger(getClass().getSimpleName());

    //verifies we cna create any reconciler from the factory using its string
    @Test
    void testFromSimple() {
        Reconciler simple = ReconcilerFactory.createReconciler(ReconcilerFactory.SIMPLE);
        log.error("From Simple: {}", simple.getClass());
        assertTrue(simple instanceof SimpleReconciler);
    }

    @Test
    void testFromStanfordSimple() {
        Reconciler stanfordSimple = ReconcilerFactory.createReconciler(ReconcilerFactory.STANFORD_SIMPLE_NLP);
        assertTrue(stanfordSimple instanceof StanfordSimpleNLPReconciler);
    }

    @Test
    void testFromStanfordCore() {
        Reconciler stanfordCore = ReconcilerFactory.createReconciler(ReconcilerFactory.STANFORD_CORE_NLP);
        assertTrue(stanfordCore instanceof StanfordCoreNLPReconciler);
    }

    @Test
    void testFromApacheOpen() {
        Reconciler apacheOpenNlp = ReconcilerFactory.createReconciler(ReconcilerFactory.APACHE_OPEN_NLP);
        assertTrue(apacheOpenNlp instanceof ApacheOpenNLPReconciler);
    }

    @Test
    void testFromDefault() {
        Reconciler def = ReconcilerFactory.createReconciler("DEFAULT");
        assertTrue(def instanceof SimpleReconciler);
    }
}