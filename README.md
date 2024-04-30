# checkmarx-sca-json-to-ptrac-parser
Custom stand alone parser for JSON files exported containing Checkmarx SCA vulnerabilities.

# Requirements
- [Python 3+](https://www.python.org/downloads/)
- [pip](https://pip.pypa.io/en/stable/installation/)
- [pipenv](https://pipenv.pypa.io/en/latest/install/)

# Installing
After installing Python, pip, and pipenv, run the following commands to setup the Python virtual environment.
```bash
git clone this_repo
cd path/to/cloned/repo
pipenv install
```

# Setup
After setting up the Python environment, you will need to setup a few things before you can run the script.

## JSON Data to Import
In the `config.yaml` file, the `json_files_directory` should point to the folder where you place the Checkmarx SCA JSON files you're trying to convert to PTRAC files. The default directory is 'file_to_process'. You can either create this folder in the root directory where you cloned the project, or change the directory path in the config to where you want to pull files from.

## API Version
The Api Version of the Plextrac instance you plan to import .ptrac files to is required for successful .ptrac generation. The API Version can be found at the bottom right of the Account Admin page in Plextrac. This value can be entered in the `config.yaml` file after `api_version`.

# Usage
After setting everything up you can run the script with the following command. You should be in the folder where you cloned the repo when running the following.
```bash
pipenv run python main.py
```

## Required Information
The following values can either be added to the `config.yaml` file or entered when prompted for when the script is run.
- API version
- Directory path to folder containing Checkmarx SCA JSON file(s) to import

## Script Execution Flow
When the script starts it will load in config values and try to:
- Read files in the specified directory

For each file found in the directory it will:
- Read and verify JSON file data is from a valid Checkmarx SCA export
- Create a temporary CSV file for easier data parsing
- Once this setup is complete it will start looping through each row in newly created temporary CSV and try to:
  - Create a new finding and add all finding information and related Package ID (which is parsed as an affected asset name).

After parsing the CSV, the script will save a .ptrac file that was parsed from the CSV.

Generated .ptrac files can be imported into an existing report in Plextrac, to import the findings it contains.
- Go to the Findings tab of a report
- Click 'Add findings' > 'File Imports'
- Select 'PlexTrac' from 'Import source' dropdown
- Select PTRAC file to import

## Logging
The script is run in INFO mode so you can see progress on the command line. A log file will be created when the script is run and saved to the root directory where the script is. You can search this file for "WARNING", "ERROR", "CRITICAL", or "EXCEPTION" to see if something did not get parsed or imported correctly. Any critical level issue will stop the script immediately.
