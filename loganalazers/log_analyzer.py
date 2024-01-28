#!/usr/bin/env python
# -*- coding: utf-8 -*-


# log_format ui_short '$remote_addr  $remote_user $http_x_real_ip'
#                     '[$time_local] "$request" '
#                     '$status $body_bytes_sent "$http_referer" '
#                     '"$http_user_agent" "$http_x_forwarded_for"'
#                     '"$http_X_REQUEST_ID" "$http_X_RB_USER" '
#                     '$request_time';


import sys
import os
import gzip
import re
import statistics
import json
import logging
import argparse
import datetime

import collections

config = {
    "REPORT_SIZE": 1000,
    "REPORT_DIR": "./reports",
    "LOG_DIR": "./log",
    "CONFIG_PATH": "./config/config.json",
    "LOGGING_FILE": "./monitoring.log",
    "ERROR_THRESHOLD_PERCENT": 10
}


log_form = "(?P<remote_addr>.*)\s(?P<remote_user>.*)\s\s" \
    "(?P<http_x_real_ip>.*)\s\[(?P<time_local>.*)\]\s\"" \
    "(?P<request>.*)\"\s(?P<status>.*)\s(?P<bytes_sent>.*)\s\"" \
    "(?P<http_referer>.*)\"\s\"(?P<http_user_agent>.*)\"\s\"" \
    "(?P<http_x_forwarded_for>.*)\"\s\"(?P<http_X_REQUEST_ID>.*)\"\s\"" \
    "(?P<http_X_RB_USER>.*)\"\s(?P<request_time>.*)"


request_format = "(?P<request_method>.*)\s(?P<request_url>.*)\s" \
                 "(?P<request_protocol>.*)"

Logfile = collections.namedtuple("Logfile", "path date")


def loggingup(config):
    if config.get("LOGGING_FILE", None) is None or "":
        loggingfilename = None
    else:
        loggingfilename = config["LOGGING_FILE"]
    logging.basicConfig(
        filename=loggingfilename,
        format="[%(asctime)s] %(levelname).1s %(message)s",
        datefmt="%Y.%m.%d %H:%M:%S",
        level=logging.INFO)


def config_r(config):
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--config",
        help="path to config file",
        default=config["CONFIG_PATH"])
    args = parser.parse_args()
    with open(args.config, encoding="utf_8") as configfile:
        data = json.load(configfile)
        config.update(data)
    return config


def findlatestlog(config):

    if not os.path.isdir(config["LOG_DIR"]):
        raise FileNotFoundError

    for dirpath, dirnames, filenames in os.walk(config["LOG_DIR"]):
        maxfile = Logfile("", datetime.datetime(1, 1, 1))
        for filename in filenames:
            parsefilematch = re.match(
                r"nginx\-access\-ui\.log\-(?P<filedate>\d{8})(\.gz)?",
                filename
            )
            if parsefilematch is None:
                continue
            parsefiledate = parsefilematch.group("filedate")
            filedate = datetime.datetime.strptime(parsefiledate, "%Y%m%d")
            if filedate > maxfile.date:
                maxfile = Logfile(os.path.join(dirpath, filename), filedate)

    if not maxfile.path:
        return None
    return maxfile._replace(date=maxfile.date.strftime("%Y.%m.%d"))


def readlog_gen(logfilepathname):

    opener = gzip.open if logfilepathname.endswith(".gz") else open
    with opener(logfilepathname, mode="rt", encoding="utf_8") as logfile:
        for line in logfile:
            yield line
    logfile.close()


def parselog(log, log_format, request_format):

    result = {}
    logmatch = re.match(log_format, log)
    if logmatch is None:
        return None
    requestmatch = re.match(request_format, logmatch.group("request"))
    if requestmatch is None:
        return None
    result["request_url"] = requestmatch.group("request_url")
    result["request_time"] = float(logmatch.group("request_time"))
    return result


def analyzelog(latestlogpath, log_format, request_format, config):

    latestlog = readlog_gen(latestlogpath)
    result = {}
    totalcount = 0
    totaltime = 0
    errorlines = 0
    
    for line in latestlog:
        pars = parselog(line, log_format, request_format)
        if pars is None:
            totalcount += 1
            errorlines += 1
            continue
        if result.get(pars["request_url"]) is None:
            result[pars["request_url"]] = {}
            result[pars["request_url"]]["request_time"] = [pars["request_time"]]
        else:
            result[pars["request_url"]]["request_time"].append(pars["request_time"])
        totalcount += 1
        totaltime += pars["request_time"]
    
    for url in result:
        result[url]["count"] = len(result[url]["request_time"])
        result[url]["count_perc"] = round(
            result[url]["count"] / totalcount * 100, 3)
        result[url]["time_sum"] = round(sum(result[url]["request_time"]), 3)
        result[url]["time_perc"] = round(
            result[url]["time_sum"] / totaltime * 100, 3)
        result[url]["time_avg"] = round(
            result[url]["time_sum"] / result[url]["count"], 3)
        result[url]["time_max"] = max(result[url]["request_time"])
        result[url]["time_med"] = round(
            statistics.median(result[url]["request_time"]), 3)
        result[url]["url"] = url
        result[url].pop("request_time")
    logging.info("Analyzer ended analysis.\n"
                 "Processed %d logs.\n"
                 "Summary log request time is %.3f.\n"
                 "Parsing errors %d."
                 % (totalcount, totaltime, errorlines))

    if config.get("ERROR_THRESHOLD_PERCENT") is not None and totalcount > 0:
        if errorlines / totalcount * 100 >= config["ERROR_THRESHOLD_PERCENT"]:
            logging.error("Analyzer cannot work here. ")
            raise ValueError
    return result


def report_to(analyzeresult, reportpath, config):
    if not os.path.isdir(config["REPORT_DIR"]):
        os.mkdir(config["REPORT_DIR"])
        logging.info("Report directory %s created." % config["REPORT_DIR"])

    reporttext = json.dumps(sorted(
        list(analyzeresult.values()),
        key=lambda x: x["time_sum"],
        reverse=True)[:config["REPORT_SIZE"]])
    with open("report.html", mode="rt", encoding="utf_8") as reporttemplate:
        with open(reportpath, mode="wt", encoding="utf_8") as report:
            report.write(reporttemplate.read().replace("$table_json", reporttext))


def main(config):
    try:
        newconfig = config_r(config)
        loggingup(config)

        # Searching last file in LOG_DIR by date
        logging.info("Analyzer starts its work.")
        latestlogpath = findlatestlog(config)
        if latestlogpath is None:
            logging.error(
                "In the %s directory is nothing to analyze." % config["LOG_DIR"]
            )
            return
        logging.info("Analyzer will look at \"%s\" file." % latestlogpath.path)

        # If the report on the last date is exist, exit program
        reportpath = os.path.join(
            config["REPORT_DIR"],
            "report-%s.html" % latestlogpath.date)
        if os.path.isfile(reportpath):
            logging.info("Analyzer already worked here. Report %s on date %s "
                         "exists." % (reportpath, latestlogpath.date))
            return

        logging.info("Analyzer starts analysis.")
        analyzeresult = analyzelog(latestlogpath.path, log_form,
                                   request_format, config)

        report_to(analyzeresult, reportpath, config)
        logging.info("Analyzer created the report %s. Analyzer ended its work."
                     % reportpath)
    except:
        logging.exception("Analysis aborted.\n", exc_info=True)
    return

if __name__ == "__main__":
    sys.exit(main(config))