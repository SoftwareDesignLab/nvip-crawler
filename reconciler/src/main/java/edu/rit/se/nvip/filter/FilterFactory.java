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
package edu.rit.se.nvip.filter;

public class FilterFactory {

    public static final String SIMPLE = "SIMPLE";

    public static final String CVE_MATCHES_DESCRIPTION = "CVE_MATCHES_DESCRIPTION";

    public static final String BLANK_DESCRIPTION = "BLANK_DESCRIPTION";

    public static final String INTEGER_DESCRIPTION = "INTEGER_DESCRIPTION";

    public static final String MULTIPLE_CVE_DESCRIPTION = "MULTIPLE_CVE_DESCRIPTION";

    public static Filter createFilter(String type) {
        switch (type) {
            case SIMPLE:
                return new SimpleFilter();
            case CVE_MATCHES_DESCRIPTION:
                return new CveMatchesDescriptionFilter();
            case BLANK_DESCRIPTION:
                return new BlankDescriptionFilter();
            case INTEGER_DESCRIPTION:
                return new IntegerDescriptionFilter();
            case MULTIPLE_CVE_DESCRIPTION:
                return new MultipleCveDescriptionsFilter();
            default:
                return new SimpleFilter();
        }
    }
}
