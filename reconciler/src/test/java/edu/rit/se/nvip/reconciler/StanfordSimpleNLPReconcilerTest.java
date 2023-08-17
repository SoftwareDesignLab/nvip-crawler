package edu.rit.se.nvip.reconciler;

import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.Set;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class StanfordSimpleNLPReconcilerTest {

    private StanfordSimpleNLPReconciler stanfordSimpleNLPReconciler = new StanfordSimpleNLPReconciler();
    @Test
    void reconcileDescriptions() {
        String existingDesc = "existing desc";
        String newDesc = "new desc. longer desc.";
        Set<String> existingSourceDomains = new HashSet<>();
        String newSourceDomain = "newSource.com";
        String newDescShort = "new desc";
        assertTrue(stanfordSimpleNLPReconciler.reconcileDescriptions(existingDesc, newDesc, existingSourceDomains, newSourceDomain));
        assertFalse(stanfordSimpleNLPReconciler.reconcileDescriptions(existingDesc, newDescShort, existingSourceDomains, newSourceDomain));
        assertTrue(stanfordSimpleNLPReconciler.reconcileDescriptions(null, newDesc, existingSourceDomains, newSourceDomain));
        assertFalse(stanfordSimpleNLPReconciler.reconcileDescriptions(null, null, existingSourceDomains, newSourceDomain));

    }
}