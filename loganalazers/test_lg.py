#!/usr/bin/env python
# -*- coding: utf-8 -*-


import unittest
import log_analyzer
import os


class Testlogparsing(unittest.TestCase):
    def test_log_good(self):
        logline = (
            '1.196.116.32 -  - [29/Jun/2017:03:50:22 +0300] "GET '
            '/api/v2/banner/25019354 HTTP/1.1" 200 927 "-" "'
            "Lynx/2.8.8dev.9 libwww-FM/2.14 SSL-MM/1.4.1 GNUTLS/2."
            '10.5" "-" "1498697422-2190034393-4708-9752759" '
            '"dc7161be3" 0.390'
        )
        parseresult = {"request_url": "/api/v2/banner/25019354", "request_time": 0.390}
        testresult = log_analyzer.parselog(
            logline, log_analyzer.log_format, log_analyzer.request_format
        )
        self.assertEqual(testresult["request_url"], parseresult["request_url"])
        self.assertTrue(
            abs(testresult["request_time"] - parseresult["request_time"]) < 0.002
        )

    def test_log_empty(self):
        logline = ""
        parseresult = 1
        testresult = log_analyzer.parselog(
            logline, log_analyzer.log_format, log_analyzer.request_format
        )
        self.assertTrue(testresult == 1)


class Testanalyzing(unittest.TestCase):
    testdir = "./tests"

    @classmethod
    def setUpClass(cls):
        try:
            os.mkdir(cls.testdir)
        except FileExistsError:
            pass

    def test_empty_file(self):
        emptytestfilename = self.testdir + "/empty.txt"
        testlog = open(emptytestfilename, mode="wt")
        testlog.close()
        result = log_analyzer.analyzelog(
            emptytestfilename,
            log_analyzer.log_format,
            log_analyzer.request_format,
            log_analyzer.config,
        )
        self.assertEqual(result, {})
        os.remove(emptytestfilename)

    def test_tenline_file(self):
        tenlinefilename = self.testdir + "/tenline.txt"
        logline = (
            '1.196.116.32 -  - [29/Jun/2017:03:50:22 +0300] "GET '
            '/api/v2/banner/25019354 HTTP/1.1" 200 927 "-" "'
            "Lynx/2.8.8dev.9 libwww-FM/2.14 SSL-MM/1.4.1 GNUTLS/2."
            '10.5" "-" "1498697422-2190034393-4708-9752759" '
            '"dc7161be3" 0.390'
        )
        analyzeresult = {
            "/api/v2/banner/25019354": {
                "count": 10,
                "count_perc": 100.0,
                "time_avg": 0.39,
                "time_max": 0.39,
                "time_med": 0.39,
                "time_perc": 100.0,
                "time_sum": 3.9,
                "url": "/api/v2/banner/25019354",
            }
        }

        testlog = open(tenlinefilename, mode="wt")
        testlog.writelines([logline, "\n"] * 9)
        testlog.write(logline)
        testlog.close()
        result = log_analyzer.analyzelog(
            tenlinefilename,
            log_analyzer.log_format,
            log_analyzer.request_format,
            log_analyzer.config,
        )
        self.assertEqual(result, analyzeresult)
        os.remove(tenlinefilename)

    def test_errorlogfile(self):
        errorlogfilename = self.testdir + "/errorlog.txt"
        logline = (
            '1.196.116.32 -  - [29/Jun/2017:03:50:22 +0300] "GET '
            '/api/v2/banner/25019354 HTTP/1.1" 200 927 "-" "'
            "Lynx/2.8.8dev.9 libwww-FM/2.14 SSL-MM/1.4.1 GNUTLS/2."
            '10.5" "-" "1498697422-2190034393-4708-9752759" '
            '"dc7161be3" 0.390'
        )
        log_analyzer.config["ERROR_THRESHOLD_PERCENT"] = 10
        testlog = open(errorlogfilename, mode="wt")
        testlog.writelines([logline, "\n"] * 9)
        testlog.write("\n")
        testlog.close()
        result = log_analyzer.analyzelog(
            errorlogfilename,
            log_analyzer.log_format,
            log_analyzer.request_format,
            log_analyzer.config,
        )
        self.assertEqual(result, 1)
        os.remove(errorlogfilename)

    @classmethod
    def tearDownClass(cls):
        os.rmdir(cls.testdir)


if __name__ == "__main__":
    unittest.main()
