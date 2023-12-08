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