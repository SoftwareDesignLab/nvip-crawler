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
package edu.rit.se.nvip.reconciler;

import edu.rit.se.nvip.reconciler.models.ApacheOpenNLPModel;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * @author axoeec
 *
 */
public class ReconcilerFactory {
	private static final Logger log = LogManager.getLogger(ReconcilerFactory.class.getSimpleName());

	public static final String SIMPLE = "SIMPLE";
	public static final String STANFORD_SIMPLE_NLP = "STANFORD_SIMPLE_NLP";
	public static final String STANFORD_CORE_NLP = "STANFORD_CORE_NLP";
	public static final String APACHE_OPEN_NLP = "APACHE_OPEN_NLP";

	public static Reconciler createReconciler(String type, boolean doAttachModel) {
		
		Reconciler reconciler;

		switch (type) {
			case SIMPLE:
				reconciler = new SimpleReconciler();
				break;
			case STANFORD_SIMPLE_NLP:
				reconciler = new StanfordSimpleNLPReconciler();
				break;
			case STANFORD_CORE_NLP:
				reconciler = new StanfordCoreNLPReconciler();
				break;
			case APACHE_OPEN_NLP:
				ApacheOpenNLPReconciler out = new ApacheOpenNLPReconciler();
				if(doAttachModel) {
					out.attachModel(new ApacheOpenNLPModel());
				}
				reconciler = out;
				break;
			default:
				reconciler = new SimpleReconciler();
		}

		return reconciler;
	}
	public static Reconciler createReconciler(String type) {
		return createReconciler(type, false);
	}

}
