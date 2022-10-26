from Issue import Issue
from AnalyzeToolConfig import AnalyzeToolConfig
from collections import OrderedDict
import xml.etree.ElementTree as ET
from xml.dom.minidom import parseString
import os
from pylab import *
import csv
import sys


def file_line_error_header(file_path):
    if os.path.exists(file_path):
        os.remove(file_path)
    sys.stdout = open(file_path,"w")
    print("Code, Label")
    sys.stdout = sys.__stdout__

if __name__ == '__main__':
  eTree = ET.parse('./tmpData/existingIssues.xml')
  path_result = 'CWE758.csv'
  root = eTree.getroot()
  
  f = open(path_result, 'w')
  writer = csv.writer(f)
  writer.writerow(["code", "label"])

  for files in root:
    for file in files.iter("file"):
      fileName = os.path.basename(file.get("path"))
      if("w32" in fileName or "wchar" in fileName):
        continue
      if("CWE758" in fileName):
        if(file.findall("issue")):
          for item in file.findall("issue"):
            path = '/home/huong/projects/VDCT2/1v3/juliet_suite-c-cplus/testcases/CWE758_Undefined_Behavior/' + fileName
            list_line = ""
            with open(path, "r") as code:
              lines = code.readlines()
              count = 0
              list_lines = ""
              for line in lines:
                count +=1
                if count >= int(item.get("startLine")) and count <= int(item.get("endLine")):
                  list_lines += line
              writer = csv.writer(f)
              writer.writerow([list_lines, "1"])
  f.close()  
      
    