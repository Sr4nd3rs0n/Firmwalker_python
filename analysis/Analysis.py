
import os
import sys
import pathlib
import subprocess
import binwalk
from data.dictionaries import DICTIONARIES
from syscalls.Syscalls import *
from fpdf import FPDF

################### Commands ###################
def print_path(firmdir, filename = None, output_format = None):
    if output_format == 'txt' or output_format == 'pdf':
        fl = open(filename, 'a')
        fl.write("==================== Firmware Directory ====================\n")
        fl.write(firmdir + '\n')
        fl.write("===========================================================\n\n")
        fl.close()
    else:
        print("==================== Firmware Directory ====================")
        print(firmdir)
        print("===========================================================\n")

def passfile(firmdir, passfile_dictionary, filename = None, output_format = None):

    if output_format == 'txt' or output_format == 'pdf':
        fl = open(filename, 'a')
        for value in passfile_dictionary:
            output = find_UNIX_function(firmdir, value)
            fl.write(f"#################### {value} ####################\n")
            fl.write(output)
            fl.write(f"################################################\n\n")
        fl.close()
    else:
        for value in passfile_dictionary:
            print(f"#################### {value} ####################")
            print(find_UNIX_function(firmdir, value))
            print(f"################################################\n")


def sshfile(firmdir, sshfiles_dictionary, filename = None, output_format = None):

    if output_format == 'txt' or output_format == 'pdf':
        fl = open(filename, 'a')
        for value in sshfiles_dictionary:
            output = find_UNIX_function(firmdir, value)
            fl.write(f"++++++++++++++++++++ {value} ++++++++++++++++++++\n")
            fl.write(output)
            fl.write(f"++++++++++++++++++++++++++++++++++++++++++++++++\n\n")
        fl.close()
    else:
        for value in sshfiles_dictionary:
            print(f"++++++++++++++++++++ {value} ++++++++++++++++++++")
            print(find_UNIX_function(firmdir, value))
            print(f"++++++++++++++++++++++++++++++++++++++++++++++++\n")

def files(firmdir,files_dictionary, filename = None, output_format = None):

    if output_format == 'txt' or output_format == 'pdf':
        fl = open(filename, 'a')
        for value in files_dictionary:
            output = find_UNIX_function(firmdir, value)
            fl.write(f"-------------------- {value} --------------------\n")
            fl.write(output)
            fl.write(f"------------------------------------------------\n\n")
        fl.close()
    else:
        for value in files_dictionary:
            print(f"-------------------- {value} --------------------")
            print(find_UNIX_function(firmdir, value))
            print(f"------------------------------------------------\n")

def dbfiles(firmdir,dbfiles_dictionary, filename = None, output_format = None):

    if output_format == 'txt' or output_format == 'pdf':
        fl = open(filename, 'a')
        for value in dbfiles_dictionary:
            output = find_UNIX_function(firmdir, value)
            fl.write(f"@@@@@@@@@@@@@@@@@@@@ {value} @@@@@@@@@@@@@@@@@@@@\n")
            fl.write(output)
            fl.write(f"@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n\n")
        fl.close()
    else:
        for value in dbfiles_dictionary:
            print(f"@@@@@@@@@@@@@@@@@@@@ {value} @@@@@@@@@@@@@@@@@@@@")
            print(find_UNIX_function(firmdir, value))
            print(f"@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n")

def shellscripts(firmdir, shellscripts_dictionary, filename = None, output_format = None):

    if output_format == 'txt' or output_format == 'pdf':
        fl = open(filename, 'a')
        for value in shellscripts_dictionary:
            output = find_UNIX_function(firmdir, value)
            fl.write(f"____________________ {value} ____________________\n")
            fl.write(output)
            fl.write(f"________________________________________________\n\n")
        fl.close()
    else:
        for value in shellscripts_dictionary:
            print(f"____________________ {value} ____________________")
            print(find_UNIX_function(firmdir, value))
            print(f"________________________________________________\n")

def binfiles(firmdir, binfiles_dictionary, filename = None, output_format = None):

    if output_format == 'txt' or output_format == 'pdf':
        fl = open(filename, 'a')
        for value in binfiles_dictionary:
            output = find_UNIX_function(firmdir, value)
            fl.write(f"~~~~~~~~~~~~~~~~~~~~ {value} ~~~~~~~~~~~~~~~~~~~~\n")
            fl.write(output)
            fl.write(f"~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n\n")
        fl.close()
    else:
        for value in binfiles_dictionary:
            print(f"~~~~~~~~~~~~~~~~~~~~ {value} ~~~~~~~~~~~~~~~~~~~~")
            print(find_UNIX_function(firmdir, value))
            print(f"~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n")

def webservers(firmdir, webservers_dictionary, filename = None, output_format = None):
    if output_format == 'txt' or output_format == 'pdf':
        fl = open(filename, 'a')
        for value in webservers_dictionary:
            output = find_UNIX_function(firmdir, value)
            fl.write(f"******************** {value} ********************\n")
            fl.write(output)
            fl.write(f"************************************************\n\n")
        fl.close()
    else:
        for value in webservers_dictionary:
            print(f"******************** {value} ********************")
            print(find_UNIX_function(firmdir, value))
            print(f"************************************************\n")

def binaries(firmdir, binaries_dictionary, filename = None, output_format = None):

    if output_format == 'txt' or output_format == 'pdf':
        fl = open(filename, 'a')
        for value in binaries_dictionary:
            output = find_UNIX_function(firmdir, value)
            fl.write(f"%%%%%%%%%%%%%%%%%%%% {value} %%%%%%%%%%%%%%%%%%%%\n")
            fl.write(output)
            fl.write(f"%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%\n\n")
        fl.close()
    else:
        for value in binaries_dictionary:
            print(f"%%%%%%%%%%%%%%%%%%%% {value} %%%%%%%%%%%%%%%%%%%%")
            print(find_UNIX_function(firmdir, value))
            print(f"%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%\n")
########################################################################

################## Functions that uses grep or egrep command ##################
def patterns(firmdir, patterns_dicctionary, filename = None, output_format = None):

    if output_format == 'txt' or output_format == 'pdf':
        fl = open(filename, 'a')
        for value in patterns_dicctionary:
            output = grep_pattern(firmdir, value)
            fl.write(f"···················· {value} ····················\n")
            fl.write(output)
            fl.write(f"················································\n\n")
        fl.close()
    else:
        for value in patterns_dicctionary:
            print(f"···················· {value} ····················")
            print(grep_pattern(firmdir, value))
            print(f"················································\n")


def MD5_Hashes(firmdir, filename = None, output_format = None):

    if output_format == 'txt' or output_format == 'pdf':
        fl = open(filename, 'a')
        fl.write("==================== MD5 Hashes ====================\n")
        output = egrep_function(firmdir, '-sro', '\$1\$\w{8}\S{23}')
        fl.write(output)
        fl.write("===================================================\n\n")
        fl.close()
    else:
        print("==================== MD5 Hashes ====================")
        print(egrep_function(firmdir, '-sro', '\$1\$\w{8}\S{23}'))
        print("===================================================\n")


def ip_url_email(firmdir, value, regex, filename = None, output_format = None):

    fsdir = None
    for f in os.listdir(firmdir):
        if os.path.isdir(os.path.join(firmdir, f)):
            fsdir = os.path.join(firmdir, f)

    if output_format == 'txt' or output_format == 'pdf':
        fl = open(filename, 'a')
        fl.write(f"&&&&&&&&&&&&&&&&&&&& {value} &&&&&&&&&&&&&&&&&&&&\n")
        output = grep_regex(fsdir, regex)
        fl.write(output)
        fl.write(f"&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&\n\n")
        fl.close()
    else:
        print(f"&&&&&&&&&&&&&&&&&&&& {value} &&&&&&&&&&&&&&&&&&&&")
        print(grep_regex(fsdir, regex))
        print(f"&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&\n")



###############################################################################
def binwalk_execution(binary_name, filename, output_format = None):
    path_fs = "/"

    if output_format == 'txt':
        fl = open(filename+output_format, 'w')
        fl.write("«««««««««««««««««««« Binwalk Report »»»»»»»»»»»»»»»»»»»»\n")
        for module in binwalk.scan(binary_name, signature=True, quiet=True ,extract=False):
            fl.write ("%s Results:\n" % module.name)
        for result in module.results:
            fl.write ("\t%s    0x%.8X    %s\n" % (result.file.path, result.offset, result.description))
        for module in binwalk.scan(binary_name, signature=True, quiet=True ,extract=True):
            for result in module.results:
                if result.file.path in module.extractor.output:
                    # These are files that binwalk carved out of the original firmware image, a la dd
                    if result.offset in module.extractor.output[result.file.path].carved:

                        first, *middle, last = str(module.extractor.output[result.file.path].carved[result.offset]).split('/')
                        fl.write("\nCarved data from offset 0x%X to %s\n" % (result.offset,module.extractor.output[result.file.path].carved[result.offset]))
                    # These are files/directories created by extraction utilities (gunzip, tar, unsquashfs, etc)
                    if result.offset in module.extractor.output[result.file.path].extracted:
                        first, *middle, last = str(module.extractor.output[result.file.path].extracted[result.offset].files[0]).split('/')
                        fl.write("Extracted %d files from offset 0x%X to '%s' using '%s'\n" % (len(module.extractor.output[result.file.path].extracted[result.offset].files),                                                                               result.offset,                                                                         module.extractor.output[result.file.path].extracted[result.offset].files[0],                                                                                      module.extractor.output[result.file.path].extracted[result.offset].command))
        fl.write("««««««««««««««««««««««««««««»»»»»»»»»»»»»»»»»»»»»»»»»»»»\n\n")
        fl.close()

    elif output_format == 'pdf':
        aux = filename.split('.')
        fl = open(aux[0]+ '_binwalk.txt', 'w')

        for module in binwalk.scan(binary_name, signature=True, quiet=True ,extract=False):
            fl.write ("%s Results:\n" % module.name)
        for result in module.results:
            fl.write ("\t%s    0x%.8X    %s\n" % (result.file.path, result.offset, result.description))
        for module in binwalk.scan(binary_name, signature=True, quiet=True ,extract=True):
            for result in module.results:
                if result.file.path in module.extractor.output:
                    # These are files that binwalk carved out of the original firmware image, a la dd
                    if result.offset in module.extractor.output[result.file.path].carved:
                        first, *middle, last = str(module.extractor.output[result.file.path].carved[result.offset]).split('/')
                        fl.write("\nCarved data from offset 0x%X to %s\n" % (result.offset,module.extractor.output[result.file.path].carved[result.offset]))

                    # These are files/directories created by extraction utilities (gunzip, tar, unsquashfs, etc)
                    if result.offset in module.extractor.output[result.file.path].extracted:
                        first, *middle, last = str(module.extractor.output[result.file.path].extracted[result.offset].files[0]).split('/')
                        fl.write("Extracted %d files from offset 0x%X to '%s' using '%s'\n" % (len(module.extractor.output[result.file.path].extracted[result.offset].files),                                                                               result.offset,                                                                         module.extractor.output[result.file.path].extracted[result.offset].files[0],                                                                                      module.extractor.output[result.file.path].extracted[result.offset].command))
        fl.close()

    else:
        print("\n«««««««««««««««««««« Binwalk Report »»»»»»»»»»»»»»»»»»»»")
        for module in binwalk.scan(binary_name, signature=True, quiet=False, extract=True):
            for result in module.results:
                if result.file.path in module.extractor.output:
                    # These are files that binwalk carved out of the original firmware image, a la dd
                    if result.offset in module.extractor.output[result.file.path].carved:
                        first, *middle, last = str(module.extractor.output[result.file.path].carved[result.offset]).split('/')
                        print("Carved data from offset 0x%X to %s" % (result.offset,module.extractor.output[result.file.path].carved[result.offset]))
                    # These are files/directories created by extraction utilities (gunzip, tar, unsquashfs, etc)
                    if result.offset in module.extractor.output[result.file.path].extracted:
                        try:
                       	    first, *middle, last = str(module.extractor.output[result.file.path].extracted[result.offset].files[0]).split('/')
                       	except Exception as e:
                       	    print(e)
                       	    pass
                       	print(str(module.extractor.output[result.file.path].extracted[result.offset].files[0]).split('/'))
                        print("Extracted %d files from offset 0x%X to '%s' using '%s'" % (len(module.extractor.output[result.file.path].extracted[result.offset].files),                                                                               result.offset,                                                                         module.extractor.output[result.file.path].extracted[result.offset].files[0],                                                                                      module.extractor.output[result.file.path].extracted[result.offset].command))

        print("\n««««««««««««««««««««««««««««»»»»»»»»»»»»»»»»»»»»»»»»»»»»\n\n")

    for value in middle:
        path_fs += value + '/'

    return path_fs

#Function that performs the analysis.
def analysis(firmdir, full_dictionary, dic_regex, filename = None, output_format = None):
    full_dictionary = DICTIONARIES.copy()

    print_path(firmdir, filename, output_format)
    MD5_Hashes(firmdir, filename, output_format)

    for key in full_dictionary:
    	if key == 'passfiles':
    		passfile(firmdir, full_dictionary[key], filename, output_format)
    	elif key == 'sshfiles':
    		sshfile(firmdir, full_dictionary[key], filename, output_format)
    	elif key == 'files':
    		files(firmdir,full_dictionary[key], filename, output_format)
    	elif key == 'dbfiles':
    		dbfiles(firmdir,full_dictionary[key], filename, output_format)
    	elif key == 'shellscripts':
    		shellscripts(firmdir,full_dictionary[key], filename, output_format)
    	elif key == 'binfiles':
    		binfiles(firmdir,full_dictionary[key], filename, output_format)
    	elif key == 'webservers':
    		webservers(firmdir,full_dictionary[key], filename, output_format)
    	elif key == 'binaries':
    		binaries(firmdir,full_dictionary[key], filename, output_format)
    	elif key == 'patterns':
    		patterns(firmdir,full_dictionary[key], filename, output_format)

    for value in dic_regex:
    	ip_url_email(firmdir, value, dic_regex[value], filename, output_format)
