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
package edu.rit.se.nvip.crawler;

import lombok.extern.slf4j.Slf4j;

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
@Slf4j
public class SeleniumDriver {
	private static final int MAX_QUIT_TRIES = 2;
	private static final int MAX_GET_TRIES = 2;
	private static final int MAX_ACTION_TRIES = 3;

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
		options.addArguments("--headless=new","--user-agent=Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36");
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
                log.info("Retrying driver quit...");
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
                log.info("Retrying page get...");
                tries++;
            }
        }

        String html = null;
        try{
            Thread.sleep(1000);
            html = driver.getPageSource();
        } catch (TimeoutException | InterruptedException e) {
            log.warn("Unable to get {}", sSourceURL);
        }
        return html;
    }

    //TODO Maybe add retries
    public WebElement tryFindElement(By findBy){
    	WebElement element = null;
    	try{
    		element = new WebDriverWait(driver, Duration.ofSeconds(3))
                .until(driver -> driver.findElement(findBy));
      	} catch (Exception e){
      		log.warn("Finding element {} raised {}", findBy.toString(), e.getClass().getSimpleName());
            log.debug(e.toString());
      	}
        return element;
    }

    //TODO Maybe comment out log statements, maybe break on stale or move ex.
    public boolean tryClickElement(WebElement element, int timeoutDuration){
        boolean result = false;
        int attempts = 0;
        while(attempts < MAX_ACTION_TRIES) {
            try {
                new WebDriverWait(driver, Duration.ofSeconds(timeoutDuration))
                    .until(ExpectedConditions.elementToBeClickable(element));
                actions.moveToElement(element).perform();
                actions.click(element).perform();
                result = true;
                break;
            } catch(Exception e) {
                log.warn("Clicking element {} raised {}", element.getAccessibleName(), e.getClass().getSimpleName());
                log.debug(e.toString());
            }
            attempts++;
        }
        return result;
    }
    public boolean tryClickElement(By by, int timeoutDuration){
    	boolean result = false;
        int attempts = 0;
        WebElement element = null;
        while(attempts < MAX_ACTION_TRIES) {
            try {
            	element = new WebDriverWait(driver, Duration.ofSeconds(timeoutDuration))
            		.until(ExpectedConditions.elementToBeClickable(by));
                actions.moveToElement(element).perform();
                actions.click(element).perform();
                result = true;
                break;
            } catch(Exception e) {
            	log.warn("Clicking element {} raised {}", (element == null ? "" : element.getAccessibleName()), e.getClass().getSimpleName());
                log.debug(e.toString());
            }
            attempts++;
        }
        return result;
    }

    public void clickAcceptCookies() {
        try {
            WebElement cookiesButton = driver.findElement(By.xpath("//button[text()='Agree' or text()='Accept' or text()='Accept Cookies' or text()='Accept all']"));
            cookiesButton.click();
            log.info("Accepted Cookies for page " + driver.getCurrentUrl());
        } catch (NoSuchElementException e) {
            log.info("No Cookies pop-up found for page " + driver.getCurrentUrl());
        } catch (ElementNotInteractableException e) {
        	log.info("Unable to click cookies pop-up for page " + driver.getCurrentUrl());
        }
    }

    public void deleteAllCookies(){
    	try{
            driver.manage().deleteAllCookies();
        } catch (TimeoutException e) {
            log.warn("Unable to clear cookies for {}", driver.getCurrentUrl());
        }
    }
}