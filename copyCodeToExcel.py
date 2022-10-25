from AnalyzeToolConfig import AnalyzeToolConfig
from collections import OrderedDict
import xml.etree.ElementTree as ET
from xml.dom.minidom import parseString
import os
from pylab import *
import csv
import shutil
import sys
import linecache


def file_line_error_header(file_path):
    if os.path.exists(file_path):
        os.remove(file_path)
    sys.stdout = open(file_path,"w")
    print("Code, Label")
    sys.stdout = sys.__stdout__

if __name__ == '__main__':
  eTree = ET.parse('./existingIssues.xml')
  path_result = 'CWE758.csv'
  root = eTree.getroot()
  file_line_error_header(path_result)
  for files in root:
    for file in files.iter("file"):
      fileName = os.path.basename(file.get("path"))
      if("w32" in fileName or "wchar" in fileName):
        continue
      if("CWE758" in fileName):
        if(file.findall("issue")):
          for item in file.findall("issue"):
            path = '/home/huong/projects/VDCT/1v3/juliet_suite-c-cplus/testcases/CWE758_Undefined_Behavior/' + fileName
            list_line = ""
            with open(path, "r") as code:
              lines = code.readlines()
              list_line
              for line in lines:
                list_line = list_line + line
              print(list_line)
              # if not line: break
              # print(line)
              # list_line = list_line + line
              # reader = code.readlines() 
              # bad_function = reader[int(item.get("startLine")):int(item.get("endLine"))]
              # bad_fc = ''.join(bad_function)
              sys.stdout = open(path_result, "a")
              print(list_line, ",", 1)
              sys.stdout = sys.__stdout__
    
      
    