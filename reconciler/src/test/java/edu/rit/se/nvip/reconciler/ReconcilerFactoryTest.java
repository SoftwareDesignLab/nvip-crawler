package edu.rit.se.nvip.reconciler;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class ReconcilerFactoryTest {

    //verifies we cna create any reconciler from the factory using its string
    @Test
    void createReconciler() {
        Reconciler simple = ReconcilerFactory.createReconciler("SIMPLE");
        Reconciler stanfordSimple = ReconcilerFactory.createReconciler("STANFORD_SIMPLE_NLP");
        Reconciler stanfordCore = ReconcilerFactory.createReconciler("STANFORD_CORE_NLP");
        Reconciler apacheOpenNlp = ReconcilerFactory.createReconciler("APACHE_OPEN_NLP");
        Reconciler def = ReconcilerFactory.createReconciler("DEFAULT");

        assertTrue(simple instanceof SimpleReconciler);
        assertTrue(stanfordSimple instanceof StanfordSimpleNLPReconciler);
        assertTrue(stanfordCore instanceof StanfordCoreNLPReconciler);
        assertTrue(apacheOpenNlp instanceof ApacheOpenNLPReconciler);
        assertTrue(def instanceof SimpleReconciler);


    }
}