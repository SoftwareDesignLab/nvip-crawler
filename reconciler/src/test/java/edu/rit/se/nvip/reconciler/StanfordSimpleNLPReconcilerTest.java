package edu.rit.se.nvip.reconciler;

import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class StanfordSimpleNLPReconcilerTest {

    private StanfordSimpleNLPReconciler stanfordSimpleNLPReconciler = new StanfordSimpleNLPReconciler();
    @Test
    void reconcileDescriptions() {
        Map<String, Integer> mockMap = mock(Map.class);
        String existingDesc = "existing desc";
        String newDesc = "new desc. longer desc.";
        Set<String> existingSourceDomains = new HashSet<>();
        existingSourceDomains.add("mock");
        String newSourceDomain = "newSource.com";
        String newDescShort = "new desc";
        stanfordSimpleNLPReconciler.setKnownCveSources(mockMap);
        when(mockMap.containsKey(anyString())).thenReturn(true);
        assertTrue(stanfordSimpleNLPReconciler.reconcileDescriptions(existingDesc, newDesc, existingSourceDomains, newSourceDomain));
        assertFalse(stanfordSimpleNLPReconciler.reconcileDescriptions(existingDesc, newDescShort, existingSourceDomains, newSourceDomain));
        assertTrue(stanfordSimpleNLPReconciler.reconcileDescriptions(null, newDesc, existingSourceDomains, newSourceDomain));
        assertFalse(stanfordSimpleNLPReconciler.reconcileDescriptions(null, null, existingSourceDomains, newSourceDomain));

    }
}