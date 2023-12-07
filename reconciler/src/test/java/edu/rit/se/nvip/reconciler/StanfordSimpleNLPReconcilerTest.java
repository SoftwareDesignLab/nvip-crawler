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

    //verifies we can properly reconcile descriptions given different scenarios where descs are null/short, etc
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