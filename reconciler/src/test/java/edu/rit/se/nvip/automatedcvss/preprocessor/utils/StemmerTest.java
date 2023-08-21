package edu.rit.se.nvip.automatedcvss.preprocessor.utils;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class StemmerTest {

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