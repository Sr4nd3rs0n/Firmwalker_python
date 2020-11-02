import os
import sys
import subprocess

def find_UNIX_function(firmdir, value):
    command = "find " + firmdir + "-name " + value
    output = subprocess.run(command, capture_output = True, text = True, shell = True)
    return output.stdout


def grep_pattern(firmdir, value):
    command = "grep -lsirnw " + firmdir + " -e " + value
    output = subprocess.run(command, capture_output = True, text = True, shell = True)
    return output.stdout

def grep_regex(firmdir, regex):
    command = "grep -sRIEoh "+ regex + " --exclude-dir='dev' " + firmdir + " | " + "sort" + " | " + "uniq"
    output = subprocess.run(command, capture_output = True, text = True, shell = True)
    return output.stdout

def egrep_function(firmdir, flag, regex):
    command = "egrep " + flag + " " + regex + " " + firmdir
    output = subprocess.run(command, capture_output = True, text = True, shell = True)
    return output.stdout

#Check wether Shodan is installed in the computer or not, and if it's not,
#then install it.
def check_shodan():
    command2 = "pip list | grep -c 'shodan'"
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
