# Log_Analyzer

## Description:

This program is a Python log analyzer. It analyzes the log files in the specified directory and generates a report based on the analysis. The program includes functions for determining the format of logs, configuring logging, updating configuration, searching for the last log file, reading logs, parsing logs, analyzing logs and creating a report. It also handles exceptions and logs relevant messages. As a result of the analysis, the program provides statistical indicators for each unique request URL, such as the number, percentage of total requests, total request time, percentage of total request time, average request time, maximum request time and median request time. The report is generated in HTML format and saved in the specified directory.

By default, the "config" dictionary inside the file is used by log_analyzer. Its contents are merged with the config/config.ini file, with the config file taking precedence over the dictionary.

To modify the configuration, you have two options. You can either rewrite the config.ini file or specify a different config file when starting the program. Here's how you can do it:

`$ python3 log_analyzer.py --config <path_to_config>`

Testing
To run unit tests, run:

`$ python3 tests.py`
# Log_Analyzer
