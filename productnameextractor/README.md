
# NVIP Product Name Extractor

The product name extractor component of NVIP identifies affected products in a CVE via a Named Entity Recognition (NER) model.
- The model and its training data is provided in the `productnameextractor/nvip_data` directory
- Each extracted product is mapped to a Common Product Enumeration (CPE) string in NVD's official CPE Dictionary
- CPE Definition and Dictionary(s): https://nvd.nist.gov/products/cpe

> **NOTE:** This component relies directly on the vulnerability data from the crawler and reconciler and should be run after the crawler and reconciler

## System Requirements

* Product Name Extractor requires at least Java version 8.
    - Download Link: https://www.oracle.com/java/technologies/javase/javase8-archive-downloads.html


* Product Name Extractor uses MySQL (version 8) to store CVEs. The database must be created before running the system. The current database dump is provided at `nvip-crawler/nvip_data/mysql-database/newDB`. See the instructions below on initializing the database.
    - Download Link: https://dev.mysql.com/downloads/installer/


* We're also going to be using Liquibase for updating and tracking changes to the database schema.
    - Download Link: https://www.liquibase.com/download


* Java Maven is used to compile the project with its requirements.
    - Download Link: https://maven.apache.org/download.cgi


* We also use Docker for building and deploying the project, however it is not necessary for debugging and development builds.
    - Download Link: https://docs.docker.com/engine/install/


* Finally, RabbitMQ is also needed if using a queue-based system with the NVIP components (Crawler feeds Reconciler jobs, Reconciler feeds Product Name Extractor jobs, etc.).
    - Download Link: https://www.rabbitmq.com/download.html


* A minimum of 8GB RAM is needed to run the program, but 16GB is recommended.

## Summary of Open Source Technologies/Systems Used

* MySQL database is used to store products affected by CVEs: https://www.mysql.com/

* Log4j is used for logging errors and state: https://logging.apache.org/log4j/2.x/javadoc.html

* The DeepLearning4j framework is used to train Deep Learning (LSTM) models for product name extraction: https://deeplearning4j.org/

* RabbitMQ is used to pass jobs between components in the NVIP program: https://www.rabbitmq.com/

* Docker is used to containerize each component: https://www.docker.com/


# Installation and Setup Guide

## 1. Download & Install MySQL

* Download the latest MySQL installer from  https://dev.mysql.com/downloads/installer/.


* Run the downloaded file, choose “Full” installation and continue with default options.


* During the configuration of MySQL Server, when prompted for a password (for user "root"), ensure that you remember this password and store it in the HIKARI_PASSWORD environment variable (see **Environment Variables** section below).

## 2. Create Database (via MySQL Workbench & Liquibase)

* After the installation process is finished, open the "MySQL Workbench" program.


* Click on "Database/Connect To Database" menu on MySQL Workbench and Click "Ok". Enter the password you set for user "root" earlier. You should be connected to the MySQL database.


* Once you have a database created, run the following command with your specific parameters (for DB_NAME, USERNAME, and PASSWORD) in the 
`nvip-crawler/nvip_data/mysql-database/newDB` directory:

> liquibase --changeLogFile=db.init.xml --classpath=./mysql-connector-j-8.0.33.jar --url="jdbc:mysql://localhost:3306/DB_Name" --username=USERNAME --password=PASSWORD update


> **NOTE**: Please make sure the MySQL username and password parameters in the
> environment variables are updated! (Refer to **Environment Variables** section below)

## 3. Build & Package

From the `nvip-crawler/productnameextractor` directory, run the following command via terminal to install dependencies:

    $ mvn clean install

If successful, run the following command to package the Maven project into a jar file:

    $ mvn package -DskipTests`

You can also run unit tests separately with the Maven test command:

    $ mvn test

After the build process, the output jar will be located under the "target" directory of the project root.

**If you are not using Docker**, you don't have to worry about the jar file as long as it builds successfully. Otherwise, this is the Jar file that Docker will use to run the application.

## 4. Create a Configuration to run the Product Name Extractor (IntelliJ)

> **NOTE:** Intellij does not read env.list files automatically, the contents of the product name extactor env.list file can be copied directly into the menu shown in the image below. See **Environment Variables** for more information. Please ensure that the program is run with environment variables for your specific IDE configuration.
> 
> Otherwise, default environment variables will be used but this may not be compatible with your setup.
> 
> ![Screenshot](nvip_data/docs/configMenu.png)



## 5. Build and Deploy Docker Container

#### Build Crawler Image
    $ docker build -t productnameextractor .

#### Run with Env List
    $ docker run --name productnameextractor productnameextractor
	- Default value:10g
 --env-file env.list productnameextractor

Where `-m` is the maximum memory (RAM) the container can use during runtime, and `--env-file` is the path to
the environment variable file (in `.list` format)

Make sure your MySQL service is running. If not, try the following:

- (Windows) Go to services panel via windows explorer, navigate to where your MySQL service is (named MySQL80), select
  the service and click "start".


- You can verify the service running by logging into MySQL via MySQL Command Line or MySQL Workbench
  (Login will automatically fail if the service isn't running, so be sure the login credentials are correct!)


- Make sure the data directories and the database user and password in the **Environment Variables** are correct.

### Installation & Configuration Checklist
- All parameters are located in **Environment Variables**

- Required training data and resources are stored under the `productnameextractor/nvip_data` folder. Please ensure that you have downloaded the `w2v_model_250.bin` from the NVIP Google Drive (in a file called `large files`) as it is required for the NER Model to work.

## Environment Variables

The `env.list` file contains a set of environment variables that the product name extractor requires in order to run.
All environment variables contain default values if they're not specified, but it is generally advisable to have them configured to fit your workspace.

Like stated previously, you can provide these variables when running the application with Docker via the `env.list` file.
If you want to run it locally without Docker, you'll need to provide the environment variables through whatever tool or IDE you're using.

- Setting up environment variables w/ **IntelliJ**: https://www.jetbrains.com/help/objc/add-environment-variables-and-program-arguments.html


- Setting up environment variables w/ **VS Code**: https://code.visualstudio.com/remote/advancedcontainers/environment-variables





### Database Variables

* **DB_TYPE**: Database type used
    - Defaut value: `mysql`


* **HIKARI_URL**: JDBC URL used for connecting to the MySQL Database.
    - By default, assumes that application will be run with Docker.
    - Use `mysql://localhost:3306/DB_NAME?useSSL=false&allowPublicKeyRetrieval=true` for running locally 
    - Use `mysql://host.docker.internal:3306/DB_NAME?useSSL=false&allowPublicKeyRetrieval=true` to run with Docker


* **HIKARI_USER**: Database username used to login to the database
    - Default value: `root`


* **HIKARI_PASSWORD**: Database password used to login to the database
    - Default value: `root`


### Data Directory Variables

> **NOTE**: All default values for Data Directory Variables assume that the working directory is `nvip-crawler/productnameextractor`
* **RESOURCE_DIR**: Directory path for all data resources used by Product Name Extractor
    - Default value: `nvip_data`


* **DATA_DIR**: Directory within **RESOURCE_DIR** which holds data used at runtime.
    - Default value: `data`


* **NLP_DIR**: Directory within **DATA_DIR** which holds training files for the sentence model.
    - Default value: `nlp`


### RabbitMQ Variables

* **RABBIT_POLL_INTERVAL**: The time interval (in seconds) by which the Product Name Extractor will poll RabbitMQ for jobs from the Reconciler.
    - Default value: `60`


* **RABBIT_HOST**: The hostname for the RabbitMQ server.
    - Default value: `host.docker.internal`


* **RABBIT_USERNAME**: The username for the RabbitMQ server connection.
    - Default value: `guest`


* **RABBIT_PASSWORD**: The password for the RabbitMQ server connection.
    - Default value: `guest`


### Product Name Extractor Variables

* **CHAR_2_VEC_CONFIG**: Name of the configuration file for the Char2Vec model.
	- Default value: `c2v_model_config_50.json`


* **CHAR_2_VEC_WEIGHTS**: Name of the weights file for the Char2Vec model.
	- Default value: `c2v_model_weights_50.h5`


* **WORD_2_VEC**: Name of the Word2Vec file. This needs to be separately downloaded from the Google Drive and inserted into your data directory alongside the other models as its size is too big for the GitHub repository.
	- Default value: `w2v_model_250.bin`


* **NER_MODEL**: Name of the NER Model file.
	- Default value: `NERallModel.bin`


* **NER_MODEL_NORMALIZER**: Name of the NER Model Normalizer file.
	- Default value: `NERallNorm.bin`


* **SENTENCE_MODEL**: Name of the Sentence Model.
	- Default value: `en-sent.bin`


* **PRODUCT_DETECTOR_MODEL**: Name of the model used for Product Detection.
	- Default value: `en-pos-perceptron.bin`


* **NUM_THREADS**: Number of concurrent threads running to detect products for CVEs.
	- Default value: `12`


* **PRODUCT_DICT_NAME**: Name of the written CPE product dictionary file pulled from NVD's CPE Dictionary.
	- Default value: `product_dict.json`


* **REFRESH_INTERVAL**: Time interval (in days) for how often a refresh of the product dictionary should occur.
    - Default value: `1.0`


* **FULL_PULL_INTERVAL**: Time interval (in days) for how often a full pull of the product dictionary should occur.
    - Default value: `14.0`


* **TEST_MODE**: A boolean environment variable. Set to true to run the Product Name Extractor in test mode, false otherwise. This relies on the `test_vulnerabilities.csv` file in the data directory.
    - Default value: `false`


* **PRETTY_PRINT**: A boolean environment variable. Determines whether Pretty Print will be used when writing the product dictionary to `product_dict.json` file from NVD's CPE Dictionary. This results in increased storage usage.
    - Default value: `false`