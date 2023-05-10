
# NVIP - The Backend System
The NVIP back end system is scheduled to run periodically to find CVEs as soon as they are disclosed at CVE Numbering Authority(CNA) web pages. 
It scrapes disclosed CVEs, scores/characterizes them automatically and stores them into the database.

* NVIP is a full open source software vulnerability management platform developed in Java.
* It crawls provided list of vulnerability sources and creates a dynamic database of Common Vulnerabilities and Exposures (CVE). 
* NVIP provides near real time detection of disclosed vulnerabilities, characterizes them based on the NIST's Vulnerability Description Ontology (VDO). 
* NVIP automatically scores each CVE based on the Common Vulnerability Scoring System Version 3.1 specification.
* It reconciles scraped CVEs using Apache Open NLP. 
* Automatically extracts affected Common Platform Enumeration (CPE) products from free-form CVE descriptions.
* Maintains an updated list of CVE source URLs, takes a seed URL list as input and searches for additional CVE sources. 
* Compares crawled CVEs against NVD and MITRE and records the comparison results under the "output" directory. 
(If NVIP is run at date "MM/dd/yyyy", the output will be at "output//yyyyMMdd" path.) 

## System Requirements
* NVIP requires at least Java version 8.
  - Download Link: https://www.oracle.com/java/technologies/javase/javase8-archive-downloads.html


* It uses MySQL (version 8) to store CVEs. The database muste be created before running the system. The current database dump is provided at '/nvip_data/mysql-database'. 
  - Download Link: https://dev.mysql.com/downloads/installer/


* Java Maven is used to compile the project with its requirements.
  - Download Link: https://maven.apache.org/download.cgi


* We also use Docker for building and deploying the project.
  - Download Link: https://docs.docker.com/engine/install/


* Because the crawling process is a multi-threaded process and the characterization and product name extraction trains AI/ML models, minimum 8GB RAM is needed to run the system.

## Summary of Open Source Technologies/Systems Used
* NVIP uses Crawler4j to conduct multi-threaded web crawling for CVE data: https://github.com/rzo1/crawler4j

* NVIP uses WEKA (The workbench for machine learning) to train Machine Learning models for CVE characterization: https://www.cs.waikato.ac.nz/ml/weka/

* MySQL database is used to store crawled and characterized CVEs: https://www.mysql.com/

* The Apache Open NLP is used for CVE reconciliation: https://opennlp.apache.org/ 

* The DeepLearning4j framework is used to train Deep Learning (LSTM) models for product name extraction: https://deeplearning4j.org/

* NVIP also uses Log4j for logging errors and state: https://logging.apache.org/log4j/2.x/javadoc.html
# Installation and Setup Guide (Docker)

## 1. Install Docker and Build via Docker CLI

#### 1. Build Backend Image
    $ docker build -t nvip_backend .

#### 2. Run with Env List
    $ docker run -m=10g --env-file env.list nvip_backend

The env.list file contains a set of environment variables that the backend requires in order to run.
These variables contain default values for if they're not specified, but it is advised to have them configured based on your usage.

A list of the environment variables is provided below:

## Database

* HIKARI_URL: JDBC URL used for connecting to the MySQL Database.
  - There is no default value.
  - Use mysql://localhost:3306 for running locally, and mysql://host.docker.internal:3306 to run with docker


* HIKARI_USER: Database username used to login to the MySQL database
  - There is no default value
  

* HIKARI_PASSWORD: Database password used to login to the MySQL database
  - There is no default value


* NVIP_DATA_DIR: Directory path for data resources used by NVIP at runtime
  - Default value: nvip_data


* NVIP_REFRESH_NVD_LIST: Boolean parameter that determines whether or not NVIP should refresh the existing NVD data in the nvd-cve.csv file
  - Default value: true


* NVIP_PARALLEL_PROCESS_THREAD_LIMIT: Maximum # of threads for the DBParallelProcess class to use
  - Default value: 9

## Runtime Data

* NVIP_OUTPUT_DIR: Output directory path for the web crawler(s)
  - Default value: output/crawlers


* NVIP_SEED_URLS: Directory path for seed URLs .txt file for NVIP's web crawler(s)
  - Default value: nvip_data/url-sources/nvip-seeds.txt


* NVIP_WHITELIST_URLS: Directory path for whitelisted URLs/domains for NVIP's web crawler(s)
  - Default value: nvip_data/url-sources/nvip-whitelist.txt


* NVIP_ENABLE_GITHUB: Boolean parameter for enabling pulling CVEs from CVE GitHib repo: https://github.com/CVEProject/cvelist
  - Default value: true

## Crawler

* NVIP_CRAWLER_POLITENESS: Time (ms) for how long the crawler should wait for each page to load
  - Default value: 3000


* NVIP_CRAWLER_MAX_PAGES: Maximum # of pages for the crawler to navigate to
  - Default value: 3000


* NVIP_CRAWLER_DEPTH: Maximum depth for the web crawler
  - Default value: 1


* NVIP_CRAWLER_REPORT_ENABLED: Boolean parameter for enabling error report for crawler sources. Output is logged in the specified output directory
  - Default value: true


* NVIP_NUM_OF_CRAWLER: Max # of crawler threads
  - Default value: 10

## Characterizer

## Exploit Finder

## Patch Finder

## Email Notification Service



# Installation Guide (Default)

## 1. Download & Install MySQL, Create the Database
* Download “mysql-installer-community-8.0.20.0.msi” from  https://dev.mysql.com/downloads/installer/.

* Click on the downloaded file, choose “Full” installation and continue with default options.

* During the configuration of MySQL Server, when prompted for a password (for user "root"), make sure you use the "same password" that you have at "\src\main\resources\db-mysql.properties". 

  ##### Create Database
* After the setup process is finished open "MySQL Workbench" program (Click start and search for "MySQL Workbench" to find it).

* Click on "Database/Connect To Database" menu on MySQL Workbench and Click "Ok". Enter the password you set for user "root" earlier. You should be connected to the MySQL database.

* Open a new query editor in MySQL Workbench and execute the script provided at '\nvip_data\mysql-database\' to create and initialize the MySQL database.
> Please make sure the MySQL user name and password parameters in the 'db-mysql.properties' are updated! 

## 2. Build & Package
Follow the steps below to generate NVIP output jars:

*  Open command line and navigate to the nvip_backend directory. From the root of that directory, enter the following command 
to compile and package the project in a jar_::
  
  mvn clean compile assembly:single

* If unit tests fail after compiling, you can bypass tests with the following command_::

  mvn clean compile package -DskipTests

* After the build process, the output jar will be located under the "target" directory of the project root.

* Copy/Cut the outputted jar file and place it in the root of the vulnerability-intelligence-platform directory

## 3. Run the Package
* Run the jar file (nvip-1.0.jar), by opening the command prompt and executing the command "java -Xms8G -Xmx16G -jar nvip-1.0.jar".

* Make sure your MySQL service is running. If not, try the following: 

  - (Windows) Go to services panel via windows explorer, navigate to where your MySQL service is (named MySQL80), select the service and click "start"

* Make sure the two properties files (<nvip.properties> and <db-mysql.properties>) are in the same directory where you have the jar file. Otherwise, properties files in the jar (under resources) will be used. (If the properties within the jar file are wrong then you will have to adjust the properties
and create a new jar)

* Make sure the <dataDir> (in nvip.properties) points to the nvip_data directory and the database user and password in the <db-mysql.properties> are correct.

## Installation & Configuration Checklist
- There are two config files used. 'nvip.properties' is used to set program parameters, and 'db-mysql.properties' is used to set database parameters. When the system is run, the config files are first searched in the application root, if they are not found there the ones at '\src\main\resources' are used!

- Please make sure the user name and password parameters in the 'db-mysql.properties' are set correctly! The user (root) and password parameters should be the ones set while installing MySQL. 

- Required training data and resources are stored under the nvip\_data (the data directory). You need to configure the data directory of the project (in the nvip.properties) to point to the nvip_data directory. 
> The data directory of the project can be set by the "dataDir" in the nvip.properties file.
> Ex: assuming you have the data directory at C:/nvip/nvip\_data, and the NVIP backend project at C:/nvip/nvip\_backend, then you need to have dataDir=../nvip\_data in the nvip.properties.
