package model.cpe; /**
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

/**
 * ClassifiedWord class for results of words classification in the CVE description into "Software Name", "Software Version", and "Others"
 * 0 - SOFTWARE_NAME
 * 1 - SOFTWARE_VERSION
 * 2 - OTHER
 * 
 * @author Igor Khokhlov
 *
 */

public class ClassifiedWord {
	private final String word;
	private WordType assignedClass = WordType.UNDEFINED;
	private float assignedClassConfidence = 0;
	private final int numberOfClasses;
	private final float[] confidences;

	public enum WordType {
		SOFTWARE_NAME,
		SOFTWARE_VERSION,
		OTHER,
		UNDEFINED;
	}
	
	/**
	 * Class constructor
	 */
	public ClassifiedWord(String word, float[] confidences) {
		super();
		this.word = word;
	
		this.confidences = confidences;
		numberOfClasses = confidences.length;
		assignClass();
		
	}
	
	/**
	 * Assigns class with the highest confidence
	 */	
	private void assignClass() {
		
		for (int i=0; i<confidences.length; i++) {
			if(confidences[i]>assignedClassConfidence) {
				assignedClassConfidence=confidences[i];
				assignedClass=WordType.values()[i];
			}
		}	
	
	}

	/**
	 * Returns word that has been classified
	 * @return Word (strings)
	 */	
	public String getWord() {
		return word;
	}

	/**
	 * Returns assigned class of the classified word
	 * @return Class number (int)
	 */
	public WordType getAssignedClass() {
		return assignedClass;
	}

	/**
	 * Returns confidence of the assigned class of the classified word
	 * @return Confidence level (float)
	 */
	public float getAssignedClassConfidence() {
		return assignedClassConfidence;
	}

	/**
	 * Returns number of classes
	 * @return number of classes (int)
	 */
	public int getNumberOfClasses() {
		return numberOfClasses;
	}

	/**
	 * Returns all confidences of the class of the classified word
	 * @return vector of confidences (float[])
	 */
	public float[] getConfidences() {
		return confidences;
	}


	/**
	 * Sets class and its confidence of the assigned class of the classified word
	 * @param assignedClass Class number (int)
	 * @param confidence Confidence level (float)
	 */
	public void setAssignedClass(WordType assignedClass, float confidence) {
		this.assignedClass = assignedClass;
		this.assignedClassConfidence = confidence;
	}

	@Override
	public String toString() {
		
		if (word==null) {
			return "";
		}
		
		return word + ": " + assignedClass;
	}
	
	
}
