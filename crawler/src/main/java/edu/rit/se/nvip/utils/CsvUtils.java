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
package edu.rit.se.nvip.utils;

import com.opencsv.*;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * 
 * CSV Logger uses com.opencsv (Maven lib) to generate an output CSV file.
 * 
 * @author axoeec
 *
 */
public class CsvUtils {
	final static Logger logger = LogManager.getLogger(CsvUtils.class);

	private char mySeparatorChar = '|';

	/**
	 * Write list to the CSV file
	 * 
	 * @param allData    list of annotations
	 * @param filepath   full path of the output CSV
	 * @param appendMode set true in the append mode
	 */
	public int writeListToCSV(List<String[]> allData, String filepath, boolean appendMode) {
		try {
			logger.info("Writing to CSV: {}", filepath);
			FileWriter fileWriter = new FileWriter(filepath, appendMode);
			CSVWriter writer = new CSVWriter(fileWriter, mySeparatorChar, CSVWriter.NO_QUOTE_CHARACTER, CSVWriter.NO_ESCAPE_CHARACTER, CSVWriter.DEFAULT_LINE_END);
			writer.writeAll(allData);
			writer.close();
		} catch (IOException e) {
			logger.error("Exception while writing list to CSV file!" + e);
			return 0;
		}

		return allData.size();
	}

	/**
	 * Write CSV header to the <filepath>
	 * 
	 * @param filepath   full path of the output CSV
	 * @param appendMode set true in the append mode
	 */
	public boolean writeHeaderToCSV(String filepath, String[] header, boolean appendMode) {
		try {

			FileWriter fileWriter = new FileWriter(filepath, appendMode);
			CSVWriter writer = new CSVWriter(fileWriter, mySeparatorChar, CSVWriter.NO_QUOTE_CHARACTER, CSVWriter.NO_ESCAPE_CHARACTER, CSVWriter.DEFAULT_LINE_END);
			writer.writeNext(header);
			writer.close();
		} catch (IOException e) {
			logger.error("Exception while writing header to CSV file!" + e);
			return false;
		}
		return true;
	}

	public String getSeparatorCharAsRegex() {
		return "[" + mySeparatorChar + "]";
	}

	public List<String[]> getDataFromCsv(String dataPath, char separatorChar){
		this.mySeparatorChar = separatorChar;
		return getDataFromCsv(dataPath);
	}

	/**
	 * read csv
	 * 
	 * @param dataPath
	 * @return
	 */
	public List<String[]> getDataFromCsv(String dataPath) {
		List<String[]> data = new ArrayList<>();
		try {
			CSVParser csvParser = new CSVParserBuilder().withSeparator(mySeparatorChar).build();
			CSVReader reader = new CSVReaderBuilder(new FileReader(dataPath)).withCSVParser(csvParser).build();

			String[] nextLine;
			while ((nextLine = reader.readNext()) != null) {
				data.add(nextLine);
			}
		} catch (Exception e) {
			logger.error("Error while reading csv file at: {}, {}", dataPath, e.toString());
			return null;
		}
		return data;
	}

}
