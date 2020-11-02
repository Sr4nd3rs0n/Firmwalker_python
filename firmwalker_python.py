#!/usr/bin/env python

import binwalk
import os
import sys
import pathlib
import yara
import subprocess
from fpdf import FPDF
from data.dictionaries import DICTIONARIES
from analysis.Analysis import analysis, binwalk_execution
from syscalls.Syscalls import check_yara, check_fpdf
from yara_files.yara_python import *

BASE_FILE = os.path.basename(__file__)

dic_regex = {'ip':'"\\b(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\b"',
             'url':'"(http|https)://[^/\\"]+"',
             'email':'"([[:alnum:]_.-]+@[[:alnum:]_.-]+?\\.[[:alpha:].]{2,6})"'}

#Usage description
def usage():
    print(f"\nUsage: python3 {BASE_FILE} [Filet that is going to be analyzed] [Optional report storage: ...]\n")


#MSG == Write in a file.

#Check for arguments
def check_args():
    #If the number of argumets are 4 (in the case that the flag -r is introduced)
    # or in the case the user only wants to print the result at in the terminal.
    if len(sys.argv) == 4 or len(sys.argv) == 2:
        return True
    else:
        return False

def get_filename(binary):
    filename = binary
    first, *middle, last = filename.split('.')
    withoutExtention = ""
    if len(middle) != 0:
        withoutExtention += first
        for value in middle:
            withoutExtention += value + '.'
    else:
        withoutExtention += first + '.'

    return withoutExtention

def find_file(dir_init, shortname):
    absolute_path = ""
    for relative_path, dirs, files in os.walk(dir_init):
        #print("this is files: {}".format(files))
        for i in files:
            if i.endswith(shortname) == True:
                absolute_path = os.path.join(dir_init, relative_path, i)

    return absolute_path

def generate_pdf(binwalk_txt, analysis_txt, yara_txt):

    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Helvetica", size = 17)
    pdf.cell(200, 15, txt = 'This is the presentation page', ln = 1, align = 'C')

    pdf.add_page()
    pdf.set_font("Helvetica", size = 17)
    pdf.cell(200, 15, txt='Binwal Analysis', ln=1, align='C')
    pdf.set_font("Helvetica", size=10)

    file1 = open(binwalk_txt, 'r')
    for f in file1:
        pdf.multi_cell(200, 10, str(f), 'l')
    file1.close()

    pdf.add_page()
    pdf.set_font("Helvetica", size=17)
    pdf.cell(200, 15, txt='Firmwalker Analysis', ln=1, align='C')
    pdf.set_font("Helvetica", size=10)

    file2 = open(analysis_txt, 'r')

    for f2 in file2:
        pdf.multi_cell(200, 5, str(f2), 'l')
    file2.close()

    pdf.add_page()
    pdf.set_font("Helvetica", size=17)
    pdf.cell(200, 15, txt='Yara Analysis', ln=1, align='C')
    pdf.set_font("Helvetica", size=10)

    file3 = open(yara_txt, 'r')

    for f3 in file3:
        pdf.multi_cell(200, 5, str(f3), 'l')
    file3.close()

    pdf.output("final_report.pdf")


###############################################


if __name__ == "__main__":

    path_fs = ""
    interesting_files = ['.html', '.sh', '.php', '.js', '.jsp']

    if check_args():
        #If the argv 2 is -r flag and the chosen option is txt --> generate txt report.
        if len(sys.argv) == 4:
            if sys.argv[2] == "-r" and sys.argv[3] == "txt":

                filename = get_filename(sys.argv[1])
                print("Executing Binwalk, please, wait a minute.\n")
                path_fs = binwalk_execution(sys.argv[1], filename, 'txt')

                print("Executing Firmwalker analysis, please, wait a minute.\n")
                analysis(path_fs, DICTIONARIES, dic_regex, filename + 'txt', 'txt')

                print("Checking Yara.\n")
                check_yara()

                if not os.listdir("yara_files/rules"):
                    print("Downloading rules, give us a minute... \n")

		        # For the directory of the script being run
                script_path = str(pathlib.Path(__file__).parent.absolute())

                # current working directory
                #current_path = str(pathlib.Path().absolute())
                #rules_path = current_path + "yara_files/rules"
                #output_path = current_path + "yara_files/output"

                print("Writing Yara results in yara_txt.txt\n")
                scan_directory(path_fs, 'txt')
                print("Done.\n")

            #If the argv 2 is -r flag and the chosen option is pdf --> generate pdf report.
            elif sys.argv[2] == "-r" and sys.argv[3] == "pdf":
                filename = get_filename(sys.argv[1])
                filenameaux = filename.split('.')
                print(filenameaux[0])
                print("Executing Binwalk, please, wait a minute.\n")
                path_fs = binwalk_execution(sys.argv[1], filename, 'pdf')

                print("Executing Firmwalker analysis, please, wait a minute.\n")
                analysis(path_fs, DICTIONARIES, dic_regex, filenameaux[0]+'_analysis.txt', 'pdf')

                print("Checking Yara.\n")
                check_yara()

                if not os.listdir("yara_files/rules"):
                    print("Downloading rules, give us a minute... \n")

                binwalk_text = find_file(os.getcwd(), '_binwalk.txt')
                print("Writing Binwalk results in {}\n".format(binwalk_text))
                analysis_text = find_file(os.getcwd(), '_analysis.txt')
                print("Writing Firmwalker results in {}\n".format(analysis_text))

		        # For the directory of the script being run
                script_path = str(pathlib.Path(__file__).parent.absolute())

                # current working directory
                #current_path = str(pathlib.Path().absolute())
                #rules_path = current_path + "yara_files/rules"
                #output_path = current_path + "yara_files/output"

                print("Writing Yara results in yara_txt.txt\n")
                scan_directory(path_fs, 'txt')

                print("Checking FDF.\n")
                check_fpdf()

                try:
                    print("Writing report on PDF format, please wait just a little more.\n")
                    generate_pdf(binwalk_text, analysis_text, "yara_txt.txt")
                except Exception as ex:
                    print(ex)

                print("Removing binwalk txt file.\n")
                os.remove(binwalk_text)
                print("Removing analysis txt file.\n")
                os.remove(analysis_text)
                print("Removing yara txt file.\n")
                os.remove("yara_txt.txt")

                print("Done.\n")

        elif len(sys.argv) == 2:

            filename = get_filename(sys.argv[1])
            path_fs = binwalk_execution(sys.argv[1], filename, None)
            
            analysis(path_fs, DICTIONARIES, dic_regex, None, None)
            #if not os.path.exists("rules"):
            #    os.mkdir("rules")

            #if not os.path.exists("rules_compiled"):
            #    os.mkdir("rules_compiled")

            print("Checking Yara.\n")
            check_yara()

            # At this point, we've already downloaded the yara rule from github
            if not os.listdir("yara_files/rules"):
                print("Downloading rules, give us a minute... \n")

            # For the directory of the script being run
            script_path = str(pathlib.Path(__file__).parent.absolute())

            # current working directory
            #current_path = str(pathlib.Path().absolute())
            #rules_path = current_path + "yara_files/rules"
            #output_path = current_path + "yara_files/output"

            scan_directory(path_fs, None)

        else:
            print("The only two reports format supported are: txt and pdf")

    else:
        usage()
