
# NVIP Patch Finder

The Patch Finder component of NVIP identifies possible patches for products affected by CVEs.
- Patches are found by crawling available repositories for the affected products of a CVE
- Each repo is cloned, then each commit is navigated to identify patches by checking for keywords in the commit messages
- Each patch found is then stored in the database
- Product repos are cloned in the resources folder, then deleted after use
> **NOTE:** This component relies directly on the affected product data from the product name extractor and should be run after affected product data is populated in the database.

## Fix Finder Subcomponent
The Fix Finder is a subcomponent of the Patch Finder, as its goals are very similar and it is modeled
directly after the way that the PatchFinder collects and stores data. There are two main stages to the Fix
Finding process: 1) Collect the urls that will be scraped for fixes (done primarily by the FixUrlFinders),
and 2) Scrape the collected urls for vulnerability mitigation information relevant to the CVE/CPE being analyzed
(done primarily by the FixParsers).
- Done:
  - Database structure to hold found fixes and their sources.
  - API code to transport Fix data to the front-end
  - Basic abstract FixUrlFinder & FixParser implementations, these should serve as templates for all 
  host-specific implementations.
  - FixFinderEnvVars is done, with the structure for any additional necessary environment variables
  - Isolated Fix Finder component can be toggled with a single environment variable, FF_INPUT_MODE
  - Basic threading/futures implementation for scraping (FixFinderThread)
- WIP:
  - The way we source urls should be improved to include as many "good" sources as possible,
  "good" referring to reputation / completeness / chance of finding fixes.
  - The way we scrape urls needs further development and possibly further ideation to ensure
  we are getting the right data, as quickly as possible.
    - The parser system has been adapted from the Crawler htmlparser package and is more of a PoC 
    of how we could collect this data, if we find a better way, go for it.
    - A "GenericParser" class that is able to attempt to scrape fix information from a host that 
    we do not explicitly have a parser implementation for.
    - The database might even benefit from storing the parser which was used for each found fix,
    similar to the way the crawler functions with its own parsers.
  - Once this system is functioning smoothly for one/several hosts, the main development cost
  should be to create new parsers (increasing the amount of domains we can parse "perfectly").

## System Requirements

* Patch Finder requires at least Java version 8.
    - Download Link: https://www.oracle.com/java/technologies/javase/javase8-archive-downloads.html


* Patch Finder uses MySQL (version 8) to store CVEs. The database must be created before running the system. The current database dump is provided at `nvip-crawler/nvip_data/mysql-database/newDB`. See the instructions below on initializing the database.
    - Download Link: https://dev.mysql.com/downloads/installer/


* We're also going to be using Liquibase for updating and tracking changes to the database schema.
    - Download Link: https://www.liquibase.com/download


* Java Maven is used to compile the project with its requirements.
    - Download Link: https://maven.apache.org/download.cgi


* We also use Docker for building and deploying the project, however it is not necessary for debugging and development builds.
    - Download Link: https://docs.docker.com/engine/install/


* Finally, RabbitMQ is also needed if using a queue-based system with the NVIP components (Crawler feeds Reconciler jobs, Reconciler feeds Product Name Extractor jobs, etc.).
  - Download Link: https://www.rabbitmq.com/download.html


* A minimum of 4GB RAM is needed to run the program, but 8GB is recommended.

## Summary of Open Source Technologies/Systems Used

* MySQL database is used to store patches for CVEs: https://www.mysql.com/

* Log4j is used for logging errors and state: https://logging.apache.org/log4j/2.x/javadoc.html

* RabbitMQ is used to pass jobs between components in the NVIP program: https://www.rabbitmq.com/

* Docker is used to containerize each component: https://www.docker.com/


# Installation and Setup Guide

## 1. Download & Install MySQL, Create the Database

* Download the latest MySQL installer from  https://dev.mysql.com/downloads/installer/.


* Run the downloaded file, choose “Full” installation and continue with default options.


* During the configuration of MySQL Server, when prompted for a password (for user "root"), ensure that you remember this password and store it in the **HIKARI_PASSWORD** environment variable (see **Environment Variables** section below).

## 2. Create Database (via MySQL Workbench & Liquibase)

* After the installation process is finished, open the "MySQL Workbench" program.


* Click on "Database/Connect To Database" menu on MySQL Workbench and Click "Ok". Enter the password you set for user "root" earlier. You should be connected to the MySQL database.


* Once you have a database created, run the following command with your specific parameters (for DB_NAME, USERNAME, and PASSWORD) in the
  `nvip-crawler/nvip_data/mysql-database/newDB` directory:

> liquibase --changeLogFile=db.init.xml --classpath=./mysql-connector-j-8.0.33.jar --url="jdbc:mysql://localhost:3306/DB_Name" --username=USERNAME --password=PASSWORD update


> **NOTE**: Please make sure the MySQL username and password parameters in the
> environment variables are updated! (Refer to **Environment Variables** section below).

## 3. Running Locally

#### Change Working Directory:

    $ cd patchfinder

#### Install Dependencies:

    $ mvn clean install

#### Package Maven Project:

    $ mvn package -DskipTests`

#### (Optional) Run Unit Tests:

    $ mvn test

### Run Configuration
> Environment variables are set to be compatible with those running the program through Docker by default. Thus, if you are running locally, you will have to manually change the environment variables and run configuration as is applicable to your setup.
>
> Environment variables are automatically read from the env.list file by default. In order to avoid any possible errors, it is best to run the program in the `nvip-crawler/patchfinder` working directory.
>
> See **Environment Variables** below for more information.
>

## 4. Running With Docker:
Before proceeding to the following steps, please make sure that the Docker Engine is installed and running on your workstation.

#### Build & Run RabbitMQ Image:
    $ docker run -it --rm --name rabbitmq -p 5672:5672 -p 15672:15672 rabbitmq:3.12-management

#### Open New Terminal & Change Working Directory:
    $ cd patchfinder

#### Build Product Name Extractor Image:
    $ docker build -t patchfinder .

#### Run with Env List:
    $ docker run --name patchfinder -m 10GB --env-file env.list patchfinder

Where `-m` is the maximum memory (RAM) the container can use during runtime, and `--env-file` is the path to
the environment variable file (`env.list`). It is recommended to allot at least 4GB of ram during runtime.

>**NOTE**: Make sure your MySQL service is running. If not, try the following:
>
> - If on Windows, go to services panel via Windows Explorer, navigate to where your MySQL service is (named MySQL80), select
    >  the service and click `start`.
>
>
> - Verify the service is running by logging into MySQL via MySQL Command Line or MySQL Workbench
    >  (login will automatically fail if the service isn't running).
>
>
> - Make sure the database user and password as well as the hikari URL in the **Environment Variables** are correct.

### Installation & Configuration Checklist
- All environment variables are correctly configured in file `env.list`.


## Environment Variables

The `env.list` file contains a set of environment variables that the Patch Finder requires in order to run.
All environment variables contain default values if they're not specified, but it is generally advisable to have them configured to fit your workspace.

As stated previously, you can provide these variables when running the application with Docker via the `env.list` file.
If you want to run it locally without Docker, the program will attempt to automatically read from the `env.list` file. For this to work correctly, please ensure that your working directory is `nvip-crawler/patchfinder`. You also may manually configure the environment variables using your IDE if you prefer.

- Setting up environment variables with **IntelliJ**: https://www.jetbrains.com/help/objc/add-environment-variables-and-program-arguments.html


- Setting up environment variables with **VS Code**: https://code.visualstudio.com/remote/advancedcontainers/environment-variables





### Database Variables

* **DB_TYPE**: Database type used.
  - Default value: `mysql`


* **HIKARI_URL**: JDBC URL used for connecting to the MySQL Database.
  - By default, assumes that application will be run with Docker
  - Use `mysql://localhost:3306/nvip?useSSL=false&allowPublicKeyRetrieval=true` for running locally
  - Use `mysql://host.docker.internal:3306/nvip?useSSL=false&allowPublicKeyRetrieval=true` to run with Docker


* **HIKARI_USER**: Database username used to log in to the database.
  - Default value: `root`


* **HIKARI_PASSWORD**: Database password used to log in to the database.
  - Default value: `root`



### RabbitMQ Variables

* **RABBIT_POLL_INTERVAL**: The time interval (in seconds) by which the Patch Finder will poll RabbitMQ for jobs from the Product Name Extractor.
  - Default value: `60`


* **RABBIT_HOST**: The hostname for the RabbitMQ server.
  - Default value: `host.docker.internal`


* **RABBIT_VHOST**: The virtual host for the RabbitMQ server.
  - Default value: `/`


* **RABBIT_PORT**: The port for the RabbitMQ server.
  - Default value: `5672`


* **RABBIT_USERNAME**: The username for the RabbitMQ server connection.
  - Default value: `guest`


* **RABBIT_PASSWORD**: The password for the RabbitMQ server connection.
  - Default value: `guest`


### Patch Finder Variables

* **PF_INPUT_MODE**: Method of input for Patch Finder jobs, either 'db' or 'rabbit'.
  - Default value: `rabbit`


* **PF_INPUT_QUEUE**: Input message queue for Patch Finder jobs, either 'db' or 'rabbit'.
  - Default value: `PNE_OUT_PATCH`


* **FF_INPUT_QUEUE**: Input message queue for Fix Finder jobs, either 'db' or 'rabbit'.
  - Default value: `PNE_OUT_FIX`


* **CVE_LIMIT**: The limit for CVEs to be processed by the Patch Finder during runtime.
  - Default value: `20`


* **ADDRESS_BASES**: The URL address bases for which URLs are built upon when searching for GitHub repositories of affected products.
  - Default value: `https://www.github.com/,https://www.gitlab.com/`
  - If adding additional address bases, separate them by a comma `,` as shown above


* **MAX_THREADS**: Maximum number of concurrent threads running to identify patches for CVEs.
  - Default value: `10`


* **CLONE_COMMIT_THRESHOLD**: Minimum number of commits in a GitHub repository for it to be cloned. If less than threshold, commits are scraped instead without cloning the repository.
  - Default value: `1000`


* **CLONE_COMMIT_LIMIT**: Maximum number of commits in a GitHub repository for it to be cloned. If over the limit, the repository will be ignored.
  - Default value: `50000`


* **CLONE_PATH**: Path to the directory where GitHub repositories containing possible patches will be cloned to.
  - Default value: `nvip_data/patch-repos`


* **PATCH_SRC_URL_PATH**: Path to the dictionary containing possible patch sources.
  - Default value: `nvip_data/source_dict.json`


### Fix Finder Variables

* **FF_INPUT_MODE**: Method of input for Fix Finder jobs, either 'db' or 'rabbit'. A value not equal to these
* options will disable the fixfinder. (Default value will not run the Fix Finder)
  - Default value: ` `