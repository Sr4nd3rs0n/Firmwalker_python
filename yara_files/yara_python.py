import yara
import pathlib
import os

def is_malware(filename):
    """
    Run all the rules in the malware directory and save the match
    on the array to show them in the console
    """
    if not os.path.exists("yara_files/rules_compiled/malware"):
        os.mkdir("yara_files/rules_compiled/malware")

    rules_match = []

    for rule_file in os.listdir("yara_files/rules/malware/"):
        if not os.path.isdir("./" + rule_file):
            try:
                rule = yara.compile("yara_files/rules/malware/" + rule_file)
                rule.save("yara_files/rules_compiled/malware/" + rule_file)
                rule = yara.load("yara_files/rules_compiled/malware/" + rule_file)
                rule_match = rule.match(filename)
                if rule_match:
                    rules_match.append(rule_match)
            except:
                pass  # internal fatal error or warning
        else:
            pass
    
    if rules_match:
        return rules_match

def scan_directory(directory, output_format = None):
    """
    Get all the files in the directory to
    pass all the rules to each file found.
    """
    target_dir = os.path.abspath(directory)
    for root, _, filenames in os.walk(target_dir):
        for filename in filenames:
            file_path = str(os.path.join(root, filename))
            malicious_file = is_malware(filename=file_path)
            if malicious_file:
                if output_format == 'txt' or output_format == 'pdf':
                    f1 = open('yara_txt.txt', 'a')
                    f1.write("\nResult: ")
                    for rule_found in malicious_file:
                        try:
                            f1.write("\t {}: {}".format(rule_found[0], rule_found[0].meta['info']))
                        except:
                            f1.write('\t', rule_found)
                    f1.write("\n")
                    f1.write("=" * 50)
                    f1.close()
                    
                else:
                    print("\nResult: ")
                    for rule_found in malicious_file:
                        try:
                            print("\t {}: {}".format(rule_found[0], rule_found[0].meta['info']))
                        except:
                            print('\t', rule_found)
                    print()
                    print("=" * 50)

