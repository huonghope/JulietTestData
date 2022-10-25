#! /usr/bin/env/python 3.1
#
# main file (or entry point) for the analysis. Handles all different stuff like, collection flaws, 
# start the security scanners and generate result-reports
#
import time
import sys
from FlawCollector import FlawCollector
from AnalyzeToolConfig import AnalyzeToolConfig
import os


if __name__ == '__main__':
    config = AnalyzeToolConfig('config.cfg')
    
    startTime = time.time()
    flawCollector = FlawCollector(config)
    startFlawCollection=time.time()
    flawCollector.collect('ccpp')
    endFlawCollection=time.time()
    print("collected ccpp flaws in "+str((endFlawCollection-startFlawCollection))+" seconds")
