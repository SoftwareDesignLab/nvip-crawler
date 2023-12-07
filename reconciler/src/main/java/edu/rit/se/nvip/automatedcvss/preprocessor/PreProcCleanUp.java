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

/**
 * Copyright 2023 Rochester Institute of Technology (RIT). Developed with
 * government support under contract 70RCSA22C00000008 awarded by the United
 * States Department of Homeland Security for Cybersecurity and Infrastructure Security Agency.for Cybersecurity and Infrastructure Security Agency.
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
package edu.rit.se.nvip.automatedcvss.preprocessor;

import java.util.ArrayList;
import java.util.List;


/**
 *
 * 
 * @author Carlos Castro
 *
 *         This Pre-Processor cleans up the text, eliminating all 'non
 *         characters' (punctuation marks, numbers, etc) It is set up as a Chain
 *         of Command design pattern, where each preprocessor does its operation
 *         and calls on the next one This allows for dynamic set up of the
 *         pre-processing steps, as well as adding or removing steps later on
 *
 */
public final class PreProcCleanUp implements PreProcessor {

	// Next in the chain of command

	PreProcessor _next;

	public PreProcCleanUp() {
	}

	/**
	 *
	 * @param next
	 * @return
	 */
	public PreProcessor setNextPreProcessor(PreProcessor next) {
		// Integrity checks
		if (next == null) {
			throw new IllegalArgumentException("The next preProcessor can't be null");
		}
		// Sets the next chain link
		_next = next;
		return this;
	}

	/**
	 *
	 * @param text
	 * @return
	 */
	public List<String> process(String text) {
		String initialText = text;
		List<String> results = new ArrayList<>();
		String singleResult = "";

		// Reduces the text to only characters - using Regular Expressions
		singleResult = initialText.replaceAll("[^\\p{L}]", " ");
		// Eliminates any duplicate whitespace - using Regular Expressions
		singleResult = singleResult.replaceAll("\\s+", " ");
		results.add(singleResult);
		return results;

	}
}
