package model.cpe;

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

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import versionmanager.VersionManager;

import java.util.Arrays;
import java.util.HashSet;

/**
 * Data class to represent a version of a product. This class also contains static functionality
 * to manipulate ProductVersion instances.
 */
public class ProductVersion implements Comparable<ProductVersion> {
    private final int[] versionParts;
    private final static Logger logger = LogManager.getLogger(ProductVersion.class);

    //Set of words to be protected from removing characters
    private final static HashSet<String> protectedWords;
    static{
        protectedWords = new HashSet<>();
        protectedWords.add("earlier");
        protectedWords.add("after");
        protectedWords.add("and");
        protectedWords.add("version");
        protectedWords.add("before");
        protectedWords.add("through");
        protectedWords.add("prior");
        protectedWords.add("to");
        protectedWords.add("versions");
        protectedWords.add("between");
        protectedWords.add("later");
    }

    /**
     * Constructor for ProductVersion. Takes in a string such as "1.2" and turns it into an array of parts,
     * separating into [1, 2]. This allows the versionParts to be parsed to compare ProductVersion objects
     * to each other.
     *
     * Handles cases with bad format such as "1.2," or "v1.2"
     *
     * @param versionString string representation of a version
     * @throws IllegalArgumentException for incorrectly formatted version strings
     */
    public ProductVersion(String versionString) throws IllegalArgumentException {

        //Change versionString into acceptable form
        versionString = formatVersionWord(versionString);

        // Ensure provided version is valid
        if(!VersionManager.isVersion(versionString))
            throw new IllegalArgumentException("Failed to create ProductVersion from String '" + versionString + "'");

        // Split version into parts
        try {
            this.versionParts = Arrays.stream(versionString.split("\\.")).mapToInt(Integer::parseInt).toArray();
        } catch (NumberFormatException e) {
            logger.error("Failed to create ProductVersion from String '{}'", versionString);
            throw e;
        }
    }

    @Override
    public int compareTo(ProductVersion o) {
        // Extract parts lists
        int[] parts = this.versionParts;
        int[] otherParts = o.versionParts;
        int shortest = Math.min(parts.length, otherParts.length);
        for (int i = 0; i < shortest; i++) {
            // Extract part values
            int vp = parts[i];
            int otherVp = otherParts[i];

            // If greater/less, return comparison result
            if(vp < otherVp) return -1;
            else if(otherVp < vp) return 1;
            // Otherwise, continue with for loop
        }
        // If we reach the end of the loop without returning, parts were equal
        // If the versions differ in length, the longer one is greater, otherwise, they are equal
        if(parts.length == otherParts.length) return 0;
        else return parts.length > otherParts.length ? 1 : -1;
    }

    /**
     * Function to format version word into acceptable composition for isVersion() function
     * Handles cases such as "1.7," or "v1.2" to turn them into "1.7" and "1.2"
     *
     * @param versionWord string word to format
     */
    public static String formatVersionWord(String versionWord){
        //Always remove commas
        versionWord = versionWord.replace(",","");

        //If word is in protectedWords, continue
        if(protectedWords.contains(versionWord)) return versionWord;

        //Remove junk characters
        versionWord = versionWord.replace("v","");
        versionWord = versionWord.replace(")","");
        versionWord = versionWord.replace("(","");
        versionWord = versionWord.replace("a","");
        versionWord = versionWord.replace("b","");
        versionWord = versionWord.replace("c","");
        versionWord = versionWord.replace(":","");
        versionWord = versionWord.replace("r","");
        versionWord = versionWord.replace("h","");
        versionWord = versionWord.replace("_", ".");
        versionWord = versionWord.replace("p","");
        versionWord = versionWord.replace("l","");
        versionWord = versionWord.replace("t","");
        versionWord = versionWord.replace("f","");
        versionWord = versionWord.replace("o","");
        versionWord = versionWord.replace("r","");
        versionWord = versionWord.replace("m","");
        versionWord = versionWord.replace("=","");
        versionWord = versionWord.replace("/","");
        versionWord = versionWord.replace("\\","");
        versionWord = versionWord.replace("e","");
        versionWord = versionWord.replace("d","");
        versionWord = versionWord.replace(";","");
        versionWord = versionWord.replace("g","");
        versionWord = versionWord.replace("-",".");

        //Removes < and > unless it is the case of <2.4.5
        if(!versionWord.startsWith(">") && !versionWord.startsWith("<")){
            versionWord = versionWord.replace("<", "");
            versionWord = versionWord.replace(">", "");
        }

        //Keeps 5.x, but will remove 1.2x
        if(!versionWord.endsWith(".x")){
            versionWord = versionWord.replace("x","");
        }

        //Removes period at the end of a version "1.9.2." to "1.9.2"
        if(versionWord.endsWith(".")){
            versionWord = versionWord.substring(0, versionWord.length() - 1);
        }

        //Changes 2.0 to 2. Doesn't affect the version that is put into the database, but helps with compareTo
        if(versionWord.endsWith(".0")){
            versionWord = versionWord.substring(0, versionWord.length() - 2);
        }

        return versionWord;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ProductVersion that = (ProductVersion) o;
        return Arrays.equals(versionParts, that.versionParts);
    }

    @Override
    public String toString() {
        return String.join(".", Arrays.stream(this.versionParts).mapToObj(Integer::toString).toArray(String[]::new));
    }
}
