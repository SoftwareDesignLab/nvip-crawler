/**
 * Copyright 2023 Rochester Institute of Technology (RIT). Developed with
 * government support under contract 70RSAT19CB0000020 awarded by the United
 * States Department of Homeland Security.
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
package edu.rit.se.nvip.characterizer.preprocessor;

import edu.rit.se.nvip.automatedcvss.preprocessor.CvePreProcessor;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class PreProcessorTest {

	private final CvePreProcessor preProcessorRemove = new CvePreProcessor(true);
	private final CvePreProcessor preProcessorKeep = new CvePreProcessor(false);
	/**
	 * Test the existence of NVD and MITRE CVEs
	 */
	@Test
	public void testDataDirs() {

		String input = "Heap-based buffer overflow in the strip_escapes function in signal.c in GNU ed before 1.0 allows context-dependent or user-assisted attackers to execute arbitrary code via a long filename. NOTE: since ed itself does not typically run with special privileges this issue only crosses privilege boundaries when ed is invoked as a third-party component.";
		String output = "heap base buffer overflow strip escap function signal gnu ed allow context depend user assist attack execut arbitrari code filenam note ed doe typic run special privileg issu cross privileg boundari ed invok parti compon ";

		String sTemp = preProcessorRemove.preProcessLine(input);
		assertTrue(sTemp.contains(output));
	}

	@Test
	public void preProcessLineTest(){
		String testLine = "A test line for the pre processor ";
		String result = preProcessorRemove.preProcessLine(testLine);
		String result2 = preProcessorKeep.preProcessLine(testLine);
		System.out.println(result2);
		assertEquals("test line pre processor ", result);
		assertEquals("a test line for the pre processor ", result2);
	}

	@Test
	public void preProcessFileTest(){
		//
		String result = preProcessorRemove.preProcessFile("src/test/resources/preProcessorTest.txt");

		assertEquals("this, is a test line for the pre processor\n", result);
	}

}
