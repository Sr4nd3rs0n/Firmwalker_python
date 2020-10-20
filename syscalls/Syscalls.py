import os
import sys
import subprocess

def find_UNIX_function(firmdir, value):
    #subprocess.call(['find',firmdir, '-name', value])
    command = "find " + firmdir + "-name " + value
    output = subprocess.run(command, capture_output = True, text = True, shell = True)
    return output.stdout


def grep_pattern(firmdir, value):
    command = "grep -lsirnw " + firmdir + " -e " + value
    output = subprocess.run(command, capture_output = True, text = True, shell = True)
    return output.stdout
    
def grep_regex(firmdir, regex):
    command = "grep -sRIEoh "+ regex + " --exclude-dir='dev' " + firmdir + " | " + "sort" + " | " + "uniq"
    #print(command)
    output = subprocess.run(command, capture_output = True, text = True, shell = True)
    return output.stdout
    
    #Testing pipes are working properly.
    #command0 = "ls -la | grep '.py'"
    #print(command0)
    #output0 = subprocess.run(command0, capture_output = True, text = True, shell = True)
    #print(output0.stdout)

def egrep_function(firmdir, flag, regex):
    command = "egrep " + flag + " " + regex + " " + firmdir 
    output = subprocess.run(command, capture_output = True, text = True, shell = True)
    return output.stdout
    
#Check wether Shodan is installed in the computer or not, and if it's not, 
#then install it.
def check_shodan():
    #command0 = "apt list | grep -c 'python3-shodan'"
    #command1 = "apt list | grep -c 'python-shodan'"
    command2 = "pip list | grep -c 'shodan'"
    
    #output0 = subprocess.run(command0, capture_output = True, text = True, shell = True)
    #output1 = subprocess.run(command1, capture_output = True, text = True, shell = True)
    output2 = subprocess.run(command2, capture_output = True, text = True, shell = True)
    
    if int(output2.stdout) > 0:
        print("Shodan is already installed in your computer.\n")
    else:
        subprocess.call(['pip', 'install', 'shodan'])

def check_fpdf():
    command = "pip list | grep -c 'fpdf'"
    output = subprocess.run(command, capture_output = True, text = True, shell = True)
    
    if int(output.stdout) > 0:
        print("FPDF is already installed in yout computer.\n")
    else:
        subprocess.call(['pip', 'install', 'fpdf2'])

def check_yara():
    command = "pip list | grep -c 'yara-python'"
    output = subprocess.run(command, capture_output = True, text = True, shell = True)
    
    if int(output.stdout) > 0:
        print("yara-python is already installed in yout computer.\n")
    else:
        subprocess.call(['pip', 'install', 'yara-python'])






