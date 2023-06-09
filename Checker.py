
import re
import os
import sys

def main():    
    if len(sys.argv) < 3:
        print("Please re-run the script by providing at least two arguments: [SimLog] [Secret]")
        return 1

    sim_path = sys.argv[1]
    secret = sys.argv[2]
    print("TEESec Checker! ----------------> Started!")
    print("Extracting non-enclave execution cycles from log file!................")
    # Extract Host instructions and write them in another file
    secret_access_cycle = []
    inside = []
    secret_found = False
    cycle_number = 0
    with open(sim_path, 'r') as file:
        while True:
            log = file.readline()
            if not log:
                break
            length_log = len(log)
            start_index = 0
            if secret in log:
                secret_found = True
                for j in range(200):
                    log = file.readline()
                    secret_access_cycle.append(log)
                    match = re.search(r"Cycle=\s*(\d+)", log)
                    if match:
                        cycle_number = match.group()
                break

    cycle_pattern = re.compile(r"Cycle=\s*(\d+)")
    with open('./CheckerLog.txt', 'w') as file:
        if secret_found:
            line = "Enclave secret leakage detected!\n"
            line += "Secret value: " + secret + "\n"
            line += "Microarchitecture Structure: " + "Register file" + "\n"
            line += "Sim cycle No.: " + str(cycle_number) + "\n"
            line += "Here is a snapshot of current state of the processor:\n"
            line += "*********************************************************\n"
            line += "*********************************************************\n"
            meta_info = []
            meta_info.append(line)
            file.writelines(meta_info + secret_access_cycle)
        else:
            line = "NO enclave secret detected!\n"
            file.writelines(line)
    print("Finished creating CheckerLog.txt!")
    print("Done!")

if __name__ == "__main__":
    main()



"""
### Check whether we have a user page secret. If not, we should add kernel default secrets to dict_label_secrets
if not dict_label_secrets_pair:
    dict_label_secrets_pair["Kernel Secrets"] = list_kernel_secrets
# Analyzer (Beta Version)
#####################################################################
dict_label_PC = {}
dict_PC_secrets = {}
list_secrets_linenumber = []


print("Creating Label-PC pairs!................")
# Create Label-PC pairs
with open('/home/ghaniyoun/ghan/chipyard/toolchains/riscv-tools/riscv-tests/isa/rv64ui-v-AddressFooler.dump', 'r') as file:
    # read a list of lines into data
    lines = file.readlines()
    for line in lines:
        if "Permission" in line:
            space_separated = line.split(" ")
            label = space_separated[1].strip("<>:\n")
            dict_label_PC[label] = space_separated[0][11:]

"""


"""
# Create dictionary of PC, user secret pairs
if dict_label_PC:
    for key, value in dict_label_secrets_pair.items():
        PC = dict_label_PC[key]
        secret_vals = [secret for secret in value if secret not in list_kernel_secrets]
        dict_PC_secrets[PC] = secret_vals


# This dictionary is responsible to hold key, value pairs consisting of 2 permission labels as keys, all lines containing
# secrets as values
dict_post_processing = {}
"""

def search_user_secrets():
    lines = []
    last_label = False
    for key, value in dict_PC_secrets.items():
        list_PC_secrets = list(dict_PC_secrets)
        if list_PC_secrets.index(key) == (len(list_PC_secrets) - 1):
            last_label = True
        if last_label == False:
            nextkey = list_PC_secrets[list_PC_secrets.index(key) + 1]
            #print(key)
            #print(nextkey)
            PC_from = "Slot:0 (PC:0x" + key + " Valid:V "
            PC_to = "Slot:0 (PC:0x" + nextkey + " Valid:V "
            #print(PC_from)
            #print(PC_to)
            index_from = 0
            index_to = 0
            with open(sim_path, 'r') as file:
                lines = file.readlines()
                for line in reversed(lines):
                    if PC_to in line:
                        index_to = lines.index(line)
                        break
                for line in lines:
                    if PC_from in line:
                        index_from = lines.index(line)
                        break
                for i in range(index_from, index_to):
                    for entry in value:
                        str_entry = str(hex(entry))[2:]
                        if str_entry in lines[i]:
                            if (key + ":" + nextkey) in dict_post_processing.keys():
                                value_temp_list = dict_post_processing[key + ":" + nextkey]
                                value_temp_list.append(lines[i])
                                dict_post_processing[key + ":" + nextkey] = value_temp_list
                                list_secrets_linenumber.append(str(entry) + ": " + str(i))
                            else:
                                dict_post_processing[key + ":" + nextkey] = [lines[i]]
                                list_secrets_linenumber.append(str(entry) + ": " + str(i))
        else:
            PC_from = "Slot:0 (PC:0x" + key + " Valid:V "
            index_from = 0
            with open(sim_path, 'r') as file:
                lines = file.readlines()
                for line in lines:
                    if PC_from in line:
                        index_from = lines.index(line)
                        break
                for i in range(index_from, len(lines) - 1):
                    for entry in value:
                        str_entry = str(hex(entry))[2:]
                        if str_entry in lines[i]:
                            if (key + ":" + "End") in dict_post_processing.keys():
                                value_temp_list = dict_post_processing[key + ":" + "End"]
                                value_temp_list.append(lines[i])
                                dict_post_processing[key + ":" + "End"] = value_temp_list
                                list_secrets_linenumber.append(str(entry) + ": " + str(i))
                            else:
                                dict_post_processing[key + ":" + "End"] = [lines[i]]
                                list_secrets_linenumber.append(str(entry) + ": " + str(i))

list_kernel_post_processing_without8 = []
list_kernel_post_processing_just8 = []

def search_kernel_secrets():
    with open(sim_path,'r') as file:
        lines = file.readlines()
        for i in range(0, len(lines) - 1):
            for entry in list_kernel_secrets:
                str_entry = str(hex(entry))[2:]
                if str_entry in lines[i]:
                    if str_entry != "88888888":
                        list_kernel_post_processing_without8.append(lines[i])
                        list_secrets_linenumber.append(str(entry) + ": " + str(i))
                    else:
                        list_kernel_post_processing_just8.append(lines[i])
                        list_secrets_linenumber.append(str(entry) + ": " + str(i))



"""
if dict_label_PC:
    print("Looking for Kernel Secrets ------------> Started!")
    search_kernel_secrets()
    print("Looking for Kernel Secrets ------------> Successful!")
    print()
    print("Looking for User Secrets ------------> Started!")
    search_user_secrets()
    print("Looking for User Secrets ------------> Successful!")
else:
    print("Looking for Kernel Secrets ------------> Started!")
    search_kernel_secrets()
    print("Looking for Kernel Secrets ------------> Successful!")
with open('/home/ghaniyoun/ghan/chipyard/sims/verilator/UserSecrets.txt', 'w') as file:
    file.writelines(list(dict_post_processing))
with open('/home/ghaniyoun/ghan/chipyard/sims/verilator/KernelSecrets.txt', 'w') as file:
    file.writelines(list_kernel_post_processing_without8)
with open('/home/ghaniyoun/ghan/chipyard/sims/verilator/KernelSecrets.txt', 'a') as file:
    file.writelines(list_kernel_post_processing_just8)
"""


