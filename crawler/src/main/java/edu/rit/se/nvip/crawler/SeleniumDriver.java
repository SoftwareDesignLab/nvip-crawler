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
package edu.rit.se.nvip.crawler;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.openqa.selenium.WebDriver;
import io.github.bonigarcia.wdm.WebDriverManager;
import org.openqa.selenium.chrome.ChromeDriver;
import org.openqa.selenium.chrome.ChromeDriverService;
import org.openqa.selenium.chrome.ChromeOptions;
import org.openqa.selenium.remote.http.ClientConfig;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.By;
import org.openqa.selenium.interactions.Actions;
import org.openqa.selenium.support.ui.ExpectedConditions;
import org.openqa.selenium.support.ui.WebDriverWait;

import org.openqa.selenium.TimeoutException;
import org.openqa.selenium.NoSuchElementException;
import org.openqa.selenium.ElementNotInteractableException;
import org.openqa.selenium.interactions.MoveTargetOutOfBoundsException;

import java.util.Map;
import java.util.HashMap;
import java.time.Duration;

/**
 *
 * Helper class for access to a Selenium WebDriver
 *
 * @author asawtelle
 *
 */
public class SeleniumDriver {
	private static final int MAX_QUIT_TRIES = 2;
	private static final int MAX_GET_TRIES = 2;
	private static final int MAX_ACTION_TRIES = 2;

	private final Logger logger = LogManager.getLogger(getClass().getSimpleName());
	private WebDriver driver;
	private Actions actions;

	public SeleniumDriver(){
		this.driver = startDynamicWebDriver();
		this.actions = new Actions(driver);
	}

	public WebDriver getDriver(){
		return driver;
	}

	public static WebDriver startDynamicWebDriver() {
		System.setProperty("webdriver.chrome.silentOutput", "true");

		ChromeOptions options = new ChromeOptions();
		options.addArguments("--headless=new","--user-agent=Mozilla/5.0");
		options.addArguments("--remote-allow-origins=*");
		options.addArguments("--enable-javascript");
		options.addArguments("--no-sandbox");
		options.addArguments("--disable-dev-shm-usage");
		options.addArguments("--disk-cache-size=0");
		options.addArguments("--disable-gpu");
		options.addArguments("--disable-extensions");
		options.addArguments("--disable-web-security");
		options.addArguments("--disable-application-cache");
		Map<String, Object> timeouts = new HashMap<>();
		timeouts.put("implicit", 20);
		timeouts.put("pageLoad", 15000);
		timeouts.put("script", 60000);
		options.setCapability("timeouts", timeouts);

		WebDriverManager.chromedriver().setup();

		ChromeDriverService chromeDriverService = new ChromeDriverService.Builder().build();

		ClientConfig config = ClientConfig
				.defaultConfig()
				.readTimeout(Duration.ofSeconds(20));

		return new ChromeDriver(chromeDriverService, options);
	}

	public void tryDiverQuit(){
		int tries = 0;
        while (tries < MAX_QUIT_TRIES) {
            try {
                driver.quit();
                break;
            } catch (Exception e) {
                logger.info("Retrying driver quit...");
                tries++;
            }
        }
	}

	public String tryPageGet(String sSourceURL) {
        int tries = 0;
        while (tries < MAX_GET_TRIES) {
            try {
                driver.get(sSourceURL);
                break;
            } catch (TimeoutException e) {
                logger.info("Retrying page get...");
                tries++;
            }
        }

        String html = null;
        try{
            html = driver.getPageSource();
        } catch (TimeoutException e) {
            logger.warn("Unable to get {}", sSourceURL);
        }
        return html;
    }

    //TODO Maybe add retries
    public WebElement tryFindElement(By findBy){
    	WebElement element = null;
    	try{
    		new WebDriverWait(driver, Duration.ofSeconds(3))
          		.until(driver -> driver.findElement(findBy);
      	} catch (NoSuchElementException e){
      		logger.warn("Finding element {} raised NoSuchElementException", xpath);
      	} catch (TimeoutException e){
      		logger.warn("Finding element {} raised TimeoutException", xpath);
      	}
        return element;
    }

    //TODO Maybe comment out logger statements, maybe break on stale or move ex.
    public void tryClickElement(WebElement element, int timeoutDuration){
    	boolean result = false;
        int attempts = 0;
        while(attempts < MAX_ACTION_TRIES) {
            try {
            	new WebDriverWait(driver, Duration.ofSeconds(timeoutDuration))
            		.until(ExpectedConditions.elementToBeClickable(rowElement));
                actions.moveToElement(element).perform();
                actions.click(element).perform();
                result = true;
                break;
            } catch(StaleElementReferenceException e) {
            	logger.warn("Clicking element {} raised StaleElementReferenceException", element.getAccessibleName());
            } catch (MoveTargetOutOfBoundsException e) {
            	logger.warn("Clicking element {} raised MoveTargetOutOfBoundsException", element.getAccessibleName());
            } catch (TimeoutException e){
            	logger.warn("Clicking element {} raised TimeoutException", element.getAccessibleName());
            }
            attempts++;
        }
        return result;
    }

    public void clickAcceptCookies() {
        try {
            WebElement cookiesButton = driver.findElement(By.xpath("//button[text()='Agree' or text()='Accept' or text()='Accept Cookies' or text()='Accept all']"));
            cookiesButton.click();
            logger.info("Accepted Cookies for page " + driver.getCurrentUrl());
        } catch (NoSuchElementException e) {
            logger.info("No Cookies pop-up found for page " + driver.getCurrentUrl());
        } catch (ElementNotInteractableException e) {
        	logger.info("Unable to click cookies pop-up for page " + driver.getCurrentUrl());
        }
    }

    public void deleteAllCookies(){
    	try{
            driver.manage().deleteAllCookies();
        } catch (TimeoutException e) {
            logger.warn("Unable to clear cookies for {}", driver.getCurrentUrl());
        }
    }
}