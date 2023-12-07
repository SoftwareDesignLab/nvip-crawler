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

package edu.rit.se.nvip.automatedcvss.preprocessor.utils;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class StemmerTest {
    //confirms the stemmer add functionality
    @Test
    void addTest() {
        Stemmer stemmer = new Stemmer();
        int count = 55;
        while(count > 0) {
            stemmer.add('c');
            count--;
        }
        Stemmer stemmer2 = new Stemmer();
        char[] word = {'w', 'o', 'r', 'd'};
        stemmer2.add(word, 4);
        char[] newWord = {'w', 'o', 'r', 'd', 'w', 'o', 'r', 'd', 'w', 'o', 'r', 'd', 'w', 'o', 'r', 'd', 'w', 'o', 'r', 'd', 'w', 'o', 'r', 'd', 'w', 'o', 'r', 'd', 'w', 'o', 'r', 'd', 'w', 'o', 'r', 'd', 'w', 'o', 'r', 'd', 'w', 'o', 'r', 'd', 'w', 'o', 'r', 'd', 'w', 'o', 'r', 'd'};
        stemmer2.add(newWord, 52);

    }
    @Test
    void stemTest() {
        //Makes sure words are stemmed correctly, prints are to confirm outputs
        Stemmer stemmer = new Stemmer();

        String[] words = {
                "caresses", "ponies", "ties", "feed", "agreed", "disabled",
                "matting", "mating", "meeting", "meetings", "bumptious", "mannerism",
                "strive", "size", "quantity", "bate", "assignment", "cement", "pants",
                "edible", "table"
        };

        for (String word : words) {
            char[] wordChars = word.toCharArray();
            stemmer.add(wordChars, wordChars.length);
            stemmer.stem();
            System.out.println("Original: " + word);
            System.out.println("Stemmed: " + stemmer.toString());
            System.out.println();
        }
    }

}