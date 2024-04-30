from typing import Union, List
import yaml
import json
import csv
import os
import time

import utils.log_handler as logger
log = logger.log
import settings
from csv_parser import CSVParser
import utils.input_utils as input
import utils.general_utils as utils



def handle_load_api_version(api_version: str, parser: CSVParser) -> None:
    if api_version == "":
        api_version = input.prompt_user(f'The Api Version of the PT instance you want to import a .ptrac to is required for successful generation.\nEnter the API Version of your instance. This can be found at the bottom right of the Account Admin page in PT')
    if len(api_version.split(".")) == 3:
        parser.doc_version = api_version
        return
    else:
        if input.retry(f'The entered value {api_version} was not a valid version'):
            return handle_load_api_version("", parser)
    

def handle_load_file(path) -> dict|None:
    # checks if the file exists - is loaded correctly - and contains some data
    try:
        with open(path, 'r', encoding='utf-8') as file:
            json_data_raw = json.load(file)
            if json_data_raw == {}:
                log.exception(f'Empty JSON file')
                return None
            return json_data_raw
    except Exception as e:
        log.exception(e)
        return None


def handle_verify_file(loaded_file_data, csv_parser: CSVParser) -> bool:
    # checks that the loaded file is valid for the script - correct report fields - has findings - correct finding fields
    # correct report fields
    root_keys = ["FullReportUrl", "RiskReportSummary", "Packages", "Vulnerabilities"]
    for key in root_keys:
        if key not in list(loaded_file_data.keys()):
            log.exception(f'Expected key \'{key}\' not found in loaded JSON')
            return False
    # has findings
    if len(loaded_file_data['Vulnerabilities']) < 1:
        log.exception(f'Loaded JSON has no Vulnerabilities')
        return False
    # correct finding fields
    finding_keys = list(loaded_file_data['Vulnerabilities'][0].keys())
    if csv_parser.get_csv_headers() != finding_keys:
        log.exception(f'Vulnerability headers read from JSON\n{finding_keys}')
        log.exception(f'Expected headers\n{csv_parser.get_csv_headers()}')
        return False
    return True


def create_temp_csv(loaded_file_data) -> List[list]:
    # determine temp CSV headers - TODO add more than just finding headers
    finding_keys = list(loaded_file_data['Vulnerabilities'][0].keys())
    temp_csv = []
    temp_csv.append(finding_keys)
    
    for vuln in loaded_file_data['Vulnerabilities']:
        # seed finding with number of possible columns determined from number of keys
        finding = []
        for i in range(len(finding_keys)):
            finding.append("")
        # parse vuln fields from JSON of finding, and add to list
        for key, value in vuln.items():
            index = finding_keys.index(key) if key in finding_keys else None
            if index != None:
                if key == "References":
                    new_value = ""
                    for item in value:
                        new_value = f'{new_value}\n{item}'
                    new_value = new_value[1:]
                    finding.insert(index, new_value)
                    finding.pop(index+1)
                elif key == "Cvss":
                    new_value = value['Score']
                    finding.insert(index, new_value)
                    finding.pop(index+1)
                else:
                    finding.insert(index, value)
                    finding.pop(index+1)
        # add parsed list of finding fields to CSV
        temp_csv.append(finding)

    # with open("temp_csv.csv",'w', newline="") as file:
    #     writer = csv.writer(file)
    #     writer.writerows(temp_csv)
    
    return temp_csv


def handle_load_headers_into_parser(csv, parser: CSVParser) -> bool:
    # setup JSON finding keys/headers into CSVParser > csv_headers_mapping dict
    headers = csv[0]

    for index, header in enumerate(headers):
        if index == 0: # handle the BOM char added to the beginning of the CSV IF it exists
            if "Title" in header and header != "Title":
                header = header[1:]
        key = parser.get_key_from_header(header)
        if key in parser.get_data_mapping_ids():
            if parser.csv_headers_mapping[header].get("matched") == None: # if there are dup column headers, use the first col found and don't override when looking at the dup
                parser.csv_headers_mapping[header]["col_index"] = index
                parser.csv_headers_mapping[header]["matched"] = True
        else:
            log.error( f'Do not have mapping object created for header <{header}>. Check csv_parser.py > csv_headers_mapping_template to add. Marking as \'no_mapping\'')

    log.success(f'Loaded column headings from temp CSV')
    return True


def handle_load_data_into_parser(csv, parser: CSVParser):
    parser.csv_data = csv[1:]
    log.success(f'Loaded data from temp CSV')
    return True

    

if __name__ == '__main__':
    for i in settings.script_info:
        print(i)
    
    with open("config.yaml", 'r') as f:
        args = yaml.safe_load(f)

    # loads and validates JSON data
    log.info(f'---Starting data loading---')
    api_version = ""
    if args.get('api_version') != None and args.get('api_version') != "":
        api_version = str(args.get('api_version'))
        log.info(f'Set API Version to \'{api_version}\' from config...')
    
    json_files_directory = ""
    if args.get('json_files_directory') != None and args.get('json_files_directory') != "":
        json_files_directory = args.get('json_files_directory')
        log.info(f'Using Checkmarx XML data file path \'{json_files_directory}\' from config...')

    file_list = []
    if os.path.exists(json_files_directory) and os.path.isdir(json_files_directory):
        files = os.listdir(json_files_directory)
        file_list = [file for file in files if os.path.isfile(os.path.join(json_files_directory, file))]
        if len(file_list) > 0:
            log.success(f'Found {len(file_list)} file(s) to process')
        else:
            log.critical(f'Could not find any files in \'{json_files_directory}\'. Exiting...')
            exit()
    else:
        log.critical(f'Could not find directory \'{json_files_directory}\'. Exiting...')
        exit()

    failed_files = []
    for file_name in file_list:
        log.info(f'Processing file \'{file_name}\'...')
        file_path = f'{json_files_directory}/{file_name}'
        csv_parser = CSVParser()
        handle_load_api_version(api_version, csv_parser)
    
        loaded_json_data = handle_load_file(file_path)
        if loaded_json_data == None:
            log.exception(f'Could not load JSON file. Skipping...')
            failed_files.append(file_name)
            continue
        if not handle_verify_file(loaded_json_data, csv_parser):
            log.exception(f'\'{file_name}\' doesn\'t appear to be a Checkmarx SCA JSON file. This script can only parser a Checkmarx SCA JSON file. Skipping...')
            failed_files.append(file_name)
            continue
    
        tmp_csv = create_temp_csv(loaded_json_data)
        handle_load_headers_into_parser(tmp_csv, csv_parser)
        handle_load_data_into_parser(tmp_csv, csv_parser)

        if not csv_parser.parse_data():
            log.exception(f'Ran into error and cannot parse data. Skipping...')
            failed_files.append(file_name)
            continue
        csv_parser.display_parser_results()
        # check to make sure we don't override existing files in the exported-ptracs directory
        existing_files = [os.path.splitext(file)[0] for file in os.listdir('exported-ptracs')]
        export_file_name = utils.increment_file_name(file_name, existing_files)
        csv_parser.save_data_as_ptrac(file_name=export_file_name)
        time.sleep(1) # required to have a minimum 1 sec delay since unique file names are determined by timestamp
        
    log.success(f'\n\nProcessed and created PTRAC files for {len(file_list)-len(failed_files)}/{len(file_list)} files in \'{json_files_directory}\'. New PTRAC file(s) can be found in \'exported-ptracs\' folder.')
    if len(failed_files) > 0:
        failed_files_str = "\n".join(failed_files)
        log.exception(f'Could not successfully process all files in the directory \'{json_files_directory}\'. Failed files:\n{failed_files_str}')
    if settings.save_logs_to_file:
        log.info(f'Additional logs were added to {log.LOGS_FILE_PATH}')
