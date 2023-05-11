
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


* NVIP uses MySQL (version 8) to store CVEs. The database muste be created before running the system. The current database dump is provided at '/nvip_data/mysql-database'. 
  - Download Link: https://dev.mysql.com/downloads/installer/


* We're also going to be using Liquibase for updating and tracking changes to the database schema.
  - Download Link: https://www.liquibase.com/download


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

# Installation and Setup Guide (w/ Docker)

## 1. Download & Install MySQL, Create the Database
* Download “mysql-installer-community-8.0.20.0.msi” from  https://dev.mysql.com/downloads/installer/.


* Click on the downloaded file, choose “Full” installation and continue with default options.


* During the configuration of MySQL Server, when prompted for a password (for user "root"), make sure you use the "same password" that you have at the **HIKARI_PASSWORD** Environment Variable.

## 2. Create Database (via MySQL Workbench)
* After the setup process is finished open "MySQL Workbench" program (Click start and search for "MySQL Workbench" to find it).


* Click on "Database/Connect To Database" menu on MySQL Workbench and Click "Ok". Enter the password you set for user "root" earlier. You should be connected to the MySQL database.


* Open a new query editor in MySQL Workbench and execute the script provided at '\nvip_data\mysql-database\CreateAndInitializeDb.sql' to create and initialize the MySQL database.
> Please make sure the MySQL user name and password parameters in the Docker 
> environment variables are updated! (Refer to **Environment Variables** section for specific DB parameters needed)

## 3. Build & Package
Make sure you can build the project before setting it up with docker
From the root directory, run the following command via cmd line to install dependencies:

    $ mvn clean install

If successful, run the following command to package the Maven project into a jar file

    $ mvn package -DskipTests`

You can also run unit tests separately with the Maven test command:

    $ mvn test

After the build process, the output jar will be located under the "target" directory of the project root.
This is the Jar file that Docker will use to run the application.
If you're using Docker (which is the prefferred way of running it), you don't have to worry about the jar file as long as it builds.


## 4. Install Docker and Build via Docker CLI

#### Build Crawler Image
    $ docker build -t crawler .

#### Run with Env List
    $ docker run -m=10g --env-file env.list crawler

Where `-m` is the maximum memory (RAM) the container can use during runtime, and `--env-file` is the path to 
the environment variable file (in `.list` format)

Make sure your MySQL service is running. If not, try the following:

  - (Windows) Go to services panel via windows explorer, navigate to where your MySQL service is (named MySQL80), select 
the service and click "start".


  - You can verify the service running by logging into MySQL via MySQL Command Line or MySQL Workbench
(Login will automatically fail if the service isn't running, so be sure the login credentials are correct!)

    
  - Make sure the **NVIP_DATA_DIR** points to the nvip_data directory and the database user and password in the **Environment Variables** are correct.

### Installation & Configuration Checklist
- Not all parameters are in **Environment Variables** at the moment.
There are two additional legacy config files used for some parameters. 
`src/main/resources/nvip.properties` is used to set program parameters, and `src/main/resources/db-mysql.properties` 
is used to set database parameters (We might not need that anymore though). When the system is run, the config files are first searched in the application root, 
if they are not found there the ones at `\src\main\resources` are used!


- Required training data and resources are stored under the `nvip_data` folder (the data directory). 
You need to configure the data directory of the project (in the **Environment Variables** and (maybe) `nvip.properties`) 
to point to the `nvip_data` directory.


### Environment Variables

The `env.list` file contains a set of environment variables that the crawler requires in order to run.
Some variables contain default values for if they're not specified, but it is advised to have them configured based on your usage.

Like stated previously, you can provide these variables when running the application with Docker via the `env.list` file.
If you want to run it locally without Docker, you'll need to provide the environment variables through whatever tool or IDE you're using.

- Setting up environment variables w/ **IntelliJ**: https://www.jetbrains.com/help/objc/add-environment-variables-and-program-arguments.html


- Setting up environment variables w/ **VS Code**: https://code.visualstudio.com/remote/advancedcontainers/environment-variables

**NOTE** If you're running the application with Docker, you will not need to worry about setting up the Env Vars via your IDE.
IF there's any change in your Env Vars, you don't need to rebuild the image (unless there's changes in the code or properties files).

A list of the environment variables is provided below:

### Database

* **HIKARI_URL**: JDBC URL used for connecting to the MySQL Database.
  - There is no default value.
  - Use mysql://localhost:3306 for running locally, and mysql://host.docker.internal:3306 to run with docker


* **HIKARI_USER**: Database username used to login to the MySQL database
  - There is no default value
  

* **HIKARI_PASSWORD**: Database password used to login to the MySQL database
  - There is no default value


* **NVIP_DATA_DIR**: Directory path for data resources used by NVIP at runtime
  - Default value: nvip_data


* **NVIP_REFRESH_NVD_LIST**: Boolean parameter that determines whether or not NVIP should refresh the existing NVD data in the nvd-cve.csv file
  - Default value: true


* **NVIP_PARALLEL_PROCESS_THREAD_LIMIT**: Maximum # of threads for the DBParallelProcess class to use
  - Default value: 9

### Runtime Data

* **NVIP_OUTPUT_DIR**: Output directory path for the web crawler(s)
  - Default value: output/crawlers


* **NVIP_SEED_URLS**: Directory path for seed URLs .txt file for NVIP's web crawler(s)
  - Default value: nvip_data/url-sources/nvip-seeds.txt


* **NVIP_WHITELIST_URLS**: Directory path for whitelisted URLs/domains for NVIP's web crawler(s)
  - Default value: nvip_data/url-sources/nvip-whitelist.txt


* **NVIP_ENABLE_GITHUB**: Boolean parameter for enabling pulling CVEs from CVE GitHib repo: https://github.com/CVEProject/cvelist
  - Default value: true

### Crawler

* **NVIP_CRAWLER_POLITENESS**: Time (ms) for how long the crawler should wait for each page to load
  - Default value: 3000


* **NVIP_CRAWLER_MAX_PAGES**: Maximum # of pages for the crawler to navigate to
  - Default value: 3000


* **NVIP_CRAWLER_DEPTH**: Maximum depth for the web crawler
  - Default value: 1


* **NVIP_CRAWLER_REPORT_ENABLED**: Boolean parameter for enabling error report for crawler sources. Output is logged in the specified output directory
  - Default value: true


* **NVIP_NUM_OF_CRAWLER**: Max # of crawler threads
  - Default value: 10

### Characterizer

* **NVIP_CVE_CHARACTERIZATION_TRAINING_DATA_DIR**: Directory path for folder that contains Characterizer traning data
  - Default value: characterization


* **NVIP_CVE_CHARACTERIZATION_TRAINING_DATA**: List of Characterization training data files (*.csv) (Ordered aplhabetically, and separated by comma (","))
  - Default value: AttackTheater.csv,Context.csv,ImpactMethod.csv,LogicalImpact.csv,Mitigation.csv 


* **NVIP_CVE_CHARACTERIZATION_LIMIT**: Limit for maximum # of CVEs to run through the characterizer
  - Default value: 5000

### Exploit Finder

* **EXPLOIT_FINDER_ENABLED**: Boolean parameter for enabling the exploit finder
  - Default value: true

### Patch Finder

* **PATCHFINDER_ENABLED**: Boolean parameter for enabling the patch finder
  - Default value: true


* **PATCHFINDER_SOURCE_LIMIT**: Limit of maximum # of repos to scrape for patches
  - Default value: 10
  

* **PATCHFINDER_MAX_THREADS**: Limit of maximum # of threads for patch finder
  - Default value: 10


### Email Notification Service

* **NVIP_EMAIL_USER**: Email user name for NVIP notifications 
  - There is no default value.


* **NVIP_EMAIL_PASSWORD**: Email password for NVIP notifications 
  - There is no default value.


* **NVIP_EMAIL_FROM**: Email from address for NVIP notifications (data@cve.live)
  - There is no default value.


* **NVIP_EMAIL_PORT**: SMTP port # for NVIP notifications (ex. 587)
  - There is no default value.


* **NVIP_EMAIL_HOST**: SMTP host domain for NVIP notifications
  - There is no default value.


* **NVIP_EMAIL_MESSAGE_URL**: URL domain for links in NVIP email notifications (ex. http://www.cve.live)
  - There is no default value.



