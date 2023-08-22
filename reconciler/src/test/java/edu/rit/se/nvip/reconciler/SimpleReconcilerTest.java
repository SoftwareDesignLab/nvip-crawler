package edu.rit.se.nvip.reconciler;


import org.junit.Test;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import static com.google.common.base.CharMatcher.any;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class SimpleReconcilerTest {

    @Test
    public void testReconcileDescriptions() {
        Map<String, Integer> mockMap = mock(Map.class);
        SimpleReconciler reconciler = new SimpleReconciler();

        // Test case 1: existing source is known, new source is unknown
        String existingDescription1 = "Existing description";
        String newDescription1 = "New description";
        Set<String> existingSourceDomains1 = new HashSet<>();
        existingSourceDomains1.add("Known Source");
        String newSourceDomain1 = "Unknown Source";

        boolean result1 = reconciler.reconcileDescriptions(existingDescription1, newDescription1, existingSourceDomains1, newSourceDomain1);
        assertFalse(result1); // Should not update description

        // Test case 2: existing source is unknown, new source is known
        String existingDescription2 = "Existing description";
        String newDescription2 = "New description";
        Set<String> existingSourceDomains2 = new HashSet<>();
        String newSourceDomain2 = "Known Source";

        boolean result2 = reconciler.reconcileDescriptions(existingDescription2, newDescription2, existingSourceDomains2, newSourceDomain2);
        assertFalse(result2); // Should not update description

        // Test case 3: both sources are unknown, existing description is shorter
        String existingDescription3 = "Short description";
        String newDescription3 = "Longer description";
        Set<String> existingSourceDomains3 = new HashSet<>();
        String newSourceDomain3 = "Unknown Source";

        boolean result3 = reconciler.reconcileDescriptions(existingDescription3, newDescription3, existingSourceDomains3, newSourceDomain3);
        assertTrue(result3); // Should update description

        // Test case 4: both sources are unknown, existing description is longer
        String existingDescription4 = "Longer description";
        String newDescription4 = "Short description";
        Set<String> existingSourceDomains4 = new HashSet<>();
        existingSourceDomains4.add("mock string");
        String newSourceDomain4 = "Unknown Source";
        reconciler.setKnownCveSources(mockMap);
        when(mockMap.containsKey(anyString())).thenReturn(true);
        boolean result4 = reconciler.reconcileDescriptions(existingDescription4, newDescription4, existingSourceDomains4, newSourceDomain4);
        assertFalse(result4); // Should not update description
    }
}