#!/usr/bin/python
# Authors: Samuel Mergendahl and Nathan Burow 
# Copyright: MIT Lincoln Laboratory

import sys
import re
import struct
import json
import numpy as np
import matplotlib
import matplotlib.pyplot as plt

from argparse import ArgumentParser
from elftools.elf.elffile import ELFFile

# Object that helps retrieve CLA-relevant info from an ELF File 
class Tagger:

    # Initializes the Tagger Class
    def __init__(self, e, f, r_path, n):

        # Tags holds all the metadata
        self.tags = {}

        # elf holds functions to search the elffile
        #with open(e_path, "rb") as f:
        self.elf = ELFFile(e)

        # fns holds incoming metadata derived from the high-level source
        #with open(f_path, "rb") as f:
        self.fns = json.load(f)

        # res holds the path to store derived metadata
        self.res = r_path

        # bin_name holds the name of the elf binary
        self.bin_name = n

        # Main language variable defaults to c++
        self.main_lang = "c++"

        # elf assembly flavor 
        self.assembly = "x86"

    # Main function to append metadata to tags
    def tag(self, name, field, tag):

        # Adds a newly seen function to the metadata
        if name not in self.tags:
            self.tags[name] = {field:tag}

        # Adds a newly seen metadata field to an already seen function
        elif field not in self.tags[name]:
            self.tags[name][field] = tag

        # Appends metadata to an already seen field for a function
        else:
            tmp = self.tags[name][field]
            if type(tmp) is not list:
                tmp = [tmp]
            tmp.append(tag)
            self.tags[name][field] = tmp

    # Finds all the function names and initializes the tags metadata with all function names in elf
    def get_all_fns(self):

        # Check if we can use dwarf information
        if self.elf.has_dwarf_info:
            print(str(self.bin_name) + " has dwarf info!")
            dwarf_info = self.elf.get_dwarf_info()

        # Iterate through the entire symbol table
        stab = self.elf.get_section_by_name(".symtab")
        for symb in stab.iter_symbols():

            # Ignore empty, already seen, and symbol names without an address
            # TODO: should we add a not null qualifier? 
            if symb.name != "" and symb.name not in self.tags and symb["st_value"] != 0:

                # Symbol table value is virtual address, so make relative to .text
                text = self.elf.get_section_by_name(".text")
                offset = symb["st_value"] - text["sh_addr"]
                size = symb["st_size"]
                start = symb["st_value"]

                self.tag(symb.name, "addr", symb["st_value"])

    # For each function in the ELF, determine if it is a static, dynamic, closure, etc. 
    def tag_function_type(self):
        # Check if we can use dwarf information
        if self.elf.has_dwarf_info:
            print(str(self.bin_name) + " has dwarf info!")
            dwarf_info = self.elf.get_dwarf_info()

        # Iterate through the entire symbol table
        stab = self.elf.get_section_by_name(".symtab")
        for symb in stab.iter_symbols():

            # Ignore empty, null, and symbol names without an address
            if symb.name != "" and symb.name and symb["st_value"] != 0:

                # Some shorter names
                name = symb.name
                fn = symb 

                # No need to work if we already identified the type 
                if "type" not in self.tags[fn.name]:

                    # Tag v0 mangler types
                    if fn.name.startswith('_R'):

                        # Set main language global as rust since only rust uses v0
                        self.main_lang = "rust"

                        # Closure
                        if 'CN' in fn.name:
                            self.tag(name, "type", "closure")
                        # TODO: Dynamic dispatch
                        #elif 'N' in fn.name:
                        #    self.tag(name, "type", "dynamic")
                        # Generic arguments impl
                        elif 'IN' in fn.name:
                            self.tag(name, "type", "static")
                        # Inherit impl root
                        elif 'X' in fn.name:
                            self.tag(name, "type", "static")
                        # Trait impl root
                        elif 'M' in fn.name:
                            self.tag(name, "type", "static")
                        elif 'N' in fn.name:
                            self.tag(name, "type", "free_fn")

                    # Tag lagacy mangler types
                    elif fn.name.startswith('_Z'):

                        # Set main language global as c++ 
                        # (assume that rust is compiled with v0)
                        self.main_lang = "c++"

                        # TODO: More expressive function types for C++
                        if 'ZN' in fn.name:
                            self.tag(name, "type", "static")
                        else:
                            self.tag(name, "type", "free_fn")

                    # This script only analyzes v0 Rust manglers or typical C++ manglers 
                    else:
                        self.tag(name, "type", "unknown")

    # For each function in the ELF, determine if it is a C/C++ or Rust function 
    def tag_language(self):

        # Check if we can use dwarf information
        if self.elf.has_dwarf_info:
            print(str(self.bin_name) + " has dwarf info!")
            dwarf_info = self.elf.get_dwarf_info()

        # Use source level info to get language
        stab = self.elf.get_section_by_name(".symtab")
        if "rust" in self.fns.keys():
            if self.fns["rust"]:
                for rust_fn in self.fns["rust"]:
                    possible_funcs = list(filter(lambda s: rust_fn == s.name, stab.iter_symbols()))
                    for fn in possible_funcs:
                        print("tagging " + str(fn.name) + " as a rust function")
                        self.tag(fn.name, "lang", "rust")

        if "c++" in self.fns.keys():
            if self.fns["c++"]:
                for c_fn in self.fns["c++"]:
                    possible_funcs = list(filter(lambda s: c_fn == s.name, stab.iter_symbols()))
                    for fn in possible_funcs:
                        print("tagging " + str(fn.name) + " as a c++ function")
                        self.tag(fn.name, "lang", "c++")

        if "c" in self.fns.keys():
            if self.fns["c"]:
                for c_fn in self.fns["c"]:
                    possible_funcs = list(filter(lambda s: c_fn == s.name, stab.iter_symbols()))
                    for fn in possible_funcs:
                        print("tagging " + str(fn.name) + " as a c function")
                        self.tag(fn.name, "lang", "c")

        # Use name mangling info to get language
        stab = self.elf.get_section_by_name(".symtab")
        for symb in stab.iter_symbols():

            # Ignore empty, null, and symbol names without an address
            if symb.name != "" and symb.name and symb["st_value"] != 0:

                func_name = symb.name

                # No need to work if we already identified the language 
                if "lang" not in self.tags[symb.name]:
                    mangled = False

                    # Simple check to see if the name is mangled in any way
                    # I.e., if there is more than one uppercase character, assume mangled
                    # Okay to over estimate the mangled names, 
                    # as it will only underestimate the number of external functions
                    if sum(1 for c in symb.name if c.isupper()) > 0:
                        mangled = True

                    # tags the language and whether it is an external language call
                    if "lang" not in self.tags[func_name] and not mangled and self.tags[func_name]["type"] == "unknown" and self.main_lang == "c++":

                        # tag the language
                        if func_name.startswith("_"):
                            self.tag(func_name, "lang", "c")
                        else:
                            self.tag(func_name, "lang", "rust")

                        # also tag that it is an external language call
                        self.tags[func_name]["type"] = "external"

                    elif "lang" not in self.tags[func_name] and not mangled and self.tags[func_name]["type"] == "unknown" and self.main_lang == "rust":
                        # tag the language
                        if func_name.startswith("_"):
                            self.tag(func_name, "lang", "c")
                        else:
                            self.tag(func_name, "lang", "c++")

                        # also tag that it is an external language call
                        self.tags[func_name]["type"] = "external"

                    elif "lang" not in self.tags[func_name]:
                        # tag the language
                        self.tag(func_name, "lang", self.main_lang)

    # Save the collected tags metadata to a file
    def save_results(self):
        f = open(self.res, "w")
        json.dump(self.tags, f, indent=4)

# This function uses the Tagger class to generate
# the function types and language of each function in the elf file 
# Stores results in a json file
def generate_elf_metrics(elf_path, fns_path, results_path, binary):
    print("Started ELF Tagging.")
    tagger = Tagger(elf_path, fns_path, results_path, binary)

    print("Initializing tags...")
    tagger.get_all_fns()

    print("Tagging function types...")
    tagger.tag_function_type()

    print("Tagging language...")
    tagger.tag_language()

    print("Saving results...")
    tagger.save_results()

# This function generates metrics for a series of elf binaries
# file path is a text file that holds the names of a bunch of elf files
def elf_reader(file_path):

    with open(file_path) as f:
        lines = [line.rstrip() for line in f]

        for binary in lines:
            # Skip jsm executables
            if "jsm" not in binary:
                print("Generating elf metrics for: " + str(binary))
                with open("input/source-info.json", "rb") as fns:
                    try:
                        with open("input/elfs/" + str(binary) + ".elf", "rb") as e:
                            generate_elf_metrics(e, fns, "output/elf-results/" + str(binary) + "_results.json", str(binary))
                    except IOError:
                        print("Error " + str(binary) + " does not exist.")


def generate_obj_metrics(obj_path, binary):
    functionStartRegex=re.compile(r"^[\da-f]{16} <.+>:$")
    callRegex = re.compile(r"call")
    functionName=re.compile(r"<(.+)>:?$")
    indirectCallRegex = re.compile(r"call.? *")
    
    functionToCalls = {}
    curFunc = ""
    indirectCallCount = 0
    count = 0
    with open(obj_path, "r") as fp:
        for line in fp:
            function = functionStartRegex.search(line)
            if function:
                name = functionName.search(line)
                if name:
                    #print("Current Function: " + str(name.group(1))
                    #TODO: check if this function already exists and handle it
                    #gracefully if so
                    functionToCalls[name.group(1)] = []
                    if curFunc:
                        functionToCalls[curFunc].append(indirectCallCount)
                        #if indirectCallCount:
                        #    print(str(curFunc) + " has " + str(indirectCallCount) + " indirect calls")
                    indirectCallCount = 0
                    curFunc = name.group(1)
                else:
                    print("Couldn't find function name for line: " + str(line))
                    sys.exit(1)
            call = callRegex.search(line)
            if call:
                name = functionName.search(line)
                if name:
                    #print("\tCalls: " + str(name.group(1)))
                    functionToCalls[curFunc].append(name.group(1))
                else:
                    if indirectCallRegex.search(line):
                        #print("Couldn't find name for: " + str(line) + " assuming indirect call")
                        indirectCallCount += 1
                    else:
                        print("Error on line: " + str(line))
                        print("Neither direct nor indirect")
                        sys.exit(1)
            count +=1;
            if count % 1000000 == 0:
                print(str(count / float(87087059) * 100) + "% complete")
   
    with open("output/obj-results/" + str(binary) + "_results.json", "w") as fp:
        json.dump(functionToCalls, fp, indent=4)

# This function generates metrics for a series of objdumps 
# file path is a text file that holds the names of a bunch of objdump files
def obj_reader(file_path):

    with open(file_path) as f:
        lines = [line.rstrip() for line in f]

        for binary in lines:
            # Skip jsm executables
            if "jsm" not in binary:
                print("Generating obj metrics for: " + str(binary))
                generate_obj_metrics("input/objdumps/" + str(binary) + ".objdump", str(binary))

# Combine objdump file processing from output/obj-results/ into one json file
def combine_obj_results(file_path):
    full_json = {} 

    with open(file_path) as f:
        lines = [line.rstrip() for line in f]
        for binary in lines:
            try:
                with open("output/obj-results/" + str(binary) + "_results.json") as j:
                    res_data = json.load(j)

                    for fn_name in res_data.keys():
                        res_data_list = res_data[fn_name]
                        tmp_dict = {}
                        tmp_call_list = []

                        # Strip indirect calls
                        if not res_data_list:
                            num_indir_calls = float(0)
                        else:
                            num_indir_calls = res_data_list[-1]
                        tmp_dict["num_indirect_calls"] = num_indir_calls

                        # Strip dynamic calls info from name
                        tmp_dict["num_dynamic_calls"] = float(0)
                        if len(res_data_list) > 1:
                            for cs in res_data_list[0:-2]: 

                                # add @binary on the end of call site
                                if '@' in str(cs):
                                    tmp_dict["num_dynamic_calls"] = tmp_dict["num_dynamic_calls"]+1
                                else:
                                    cs = str(cs) + '@' + str(binary)

                                # add to set first to prevent duplicates 
                                tmp_set = set(tmp_call_list)
                                tmp_set = tmp_set.union(set([cs]))
                                tmp_call_list = list(tmp_set)
                                #tmp_call_list.append(cs)

                        tmp_dict["call_sites"] = tmp_call_list 

                        # Add a unique token for the function to prevent repeated functions 
                        if '@' in str(fn_name):
                            full_json[str(fn_name)] = tmp_dict 
                        else:
                            full_json[str(fn_name) + "@" + str(binary)] = tmp_dict 

            except IOError:
                print("Error " + str(binary) + " does not have any obj results.")

    f = open("output/obj-results/full.json", "w")
    json.dump(full_json, f, indent=4)

# Combine elf file processing from output/elf-results/ into one json file
def combine_elf_results(file_path):
    full_json = {} 

    with open(file_path) as f:
        lines = [line.rstrip() for line in f]
        for binary in lines:
            try:
                with open("output/elf-results/" + str(binary) + "_results.json") as j:
                    res_data = json.load(j)

                    for fn_name in res_data.keys():
                        full_json[str(fn_name) + "@" + str(binary)] = res_data[fn_name]

            except IOError:
                print("Error " + str(binary) + " does not have any elf results.")

    f = open("output/elf-results/full.json", "w")
    json.dump(full_json, f, indent=4)

# Combine elf processing with objump processing
def combine_elf_and_obj_results():
    print("Opening elf results...")
    with open("output/elf-results/full.json") as fj:
        full_json = json.load(fj)

        print("Opening objdump results...")
        with open("output/obj-results/full.json") as dj:
            dump = json.load(dj)

            print("Iterating through objdump functions for std lib call sites...")
            for name in dump.keys():
                for cs in dump[name]["call_sites"]:
                    if cs not in full_json:
                        if "+0x" not in cs:
                            if "LIBCXX" in cs or "libcxx" in cs or "LIBC++" in cs or "libc++" in cs or "GXX" in cs or "gxx" in cs: 
                                full_json[cs] = {
                                        "addr": "unknown",
                                        "type": "free_fn",
                                        "lang": "c++",
                                        "call_sites": [],
                                        "num_indirect_calls": float(0),
                                        "num_dynamic_calls": float(0),
                                        }
                            elif "LIBC" in cs or "libc" in cs or "GCC" in cs or "GXX" in cs or "NSS" in cs or "nss" in cs:
                                full_json[cs] = {
                                        "addr": "unknown",
                                        "type": "external",
                                        "lang": "c",
                                        "call_sites": [],
                                        "num_indirect_calls": float(0),
                                        "num_dynamic_calls": float(0),
                                        }

            print("Iterating through objdump functions...")
            for name in dump.keys():

                if name in full_json.keys():
                    call_list = dump[name]["call_sites"]
                    try:
                        num_indirect = float(dump[name]["num_indirect_calls"])
                        num_dynamic = float(dump[name]["num_dynamic_calls"])
                    except Exception as e:
                        print(e)
                        print("...saving as 0 instead...")
                        num_indirect = float(0) 
                        num_dynamic = float(0) 

                    # Adds a call_sites metadata field to an already seen function
                    if "call_sites" not in full_json[name]:
                        full_json[name]["call_sites"] = call_list 
                        full_json[name]["num_indirect_calls"] = num_indirect 
                        full_json[name]["num_dynamic_calls"] = num_dynamic 

                    # Appends metadata to an already seen call_cites for a function
                    else:
                        tmp = full_json[name]["call_sites"]
                        tmp_set = set(tmp)
                        tmp_set = tmp_set.union(set(call_list))
                        full_json[name]["call_cites"] = list(tmp_set)

                        full_json[name]["num_indirect_calls"] = full_json[name]["num_indirect_calls"] + num_indirect 
                        full_json[name]["num_dynamic_calls"] = full_json[name]["num_dynamic_calls"] + num_dynamic 
                else:
                    # Objdump found a function that the elf files couldn't
                    # Temporary solution: check if objdump has it as a @plt functions 
                    # Ignore all other cases
                    found = False
                    if "@plt" in name:
                        stripped_name = str(name).split('@')[0]

                        for n in full_json.keys():
                            if n.startswith(stripped_name) and not found:

                                # Same as if we found it above, but need to use n to save rather than name
                                call_list = dump[name]["call_sites"]
                                try:
                                    num_indirect = float(dump[name]["num_indirect_calls"])
                                    num_dynamic = float(dump[name]["num_dynamic_calls"])
                                except Exception as e:
                                    print(e)
                                    print("...saving as 0 instead...")
                                    num_indirect = float(0) 
                                    num_dynamic = float(0) 

                                # Adds a call_sites metadata field to an already seen function
                                if "call_sites" not in full_json[n]:
                                    full_json[n]["call_sites"] = call_list 
                                    full_json[n]["num_indirect_calls"] = num_indirect 
                                    full_json[n]["num_dynamic_calls"] = num_dynamic 

                                # Appends metadata to an already seen call_cites for a function
                                else:
                                    tmp = full_json[n]["call_sites"]
                                    tmp_set = set(tmp)
                                    tmp_set = tmp_set.union(set(call_list))
                                    full_json[n]["call_cites"] = list(tmp_set)

                                    full_json[n]["num_indirect_calls"] = full_json[n]["num_indirect_calls"] + num_indirect 
                                    full_json[n]["num_dynamic_calls"] = full_json[n]["num_dynamic_calls"] + num_dynamic 

                                found = True

                        if not found:
                            found = True

                            call_list = dump[name]["call_sites"]
                            try:
                                num_indirect = float(dump[name]["num_indirect_calls"])
                                num_dynamic = float(dump[name]["num_dynamic_calls"])
                            except Exception as e:
                                print(e)
                                print("...saving as 0 instead...")
                                num_indirect = float(0) 
                                num_dynamic = float(0) 

                            if "_Z" in name:
                                t = "unknown"
                                l = "c++"
                            else:
                                t = "external"
                                l = "c"

                            full_json[name] = {
                                    "addr": "unknown",
                                    "type": t,
                                    "lang": l,
                                    "call_sites": call_list,
                                    "num_indirect_calls": num_indirect,
                                    "num_dynamic_calls": num_dynamic,
                                    }

                    if not found:
                        print("Not in full: " + str(name))

            for name in full_json.keys():
                # ELF found a function that the objdump files couldn't
                # TODO: Should we really set this as zero, or "unknown"?

                if "call_sites" not in full_json[name]:
                    full_json[name]["call_sites"] = []
                if "num_indirect_calls" not in full_json[name]:
                    full_json[name]["num_indirect_calls"] = float(0)
                if "num_dynamic_calls" not in full_json[name]:
                    full_json[name]["num_dynamic_calls"] = float(0)


    # Save combined results
    print("Saving combined elf and objdump metadata...")
    f = open("output/metadata.json", "w")
    json.dump(full_json, f, indent=4)

# Add transfer point data to metadata using call sites and language tags
def get_transfer_points():
    print("Opening metadata to find transfer and visitor points...")
    with open("output/metadata.json") as mj:
        md = json.load(mj)

        # For each function, get a list of its call sites that cross a language
        print("Iterating through metadata functions...")
        md_keys_copy = md.keys()
        count = 0
        percent = 0

        for fn in md_keys_copy:
            print(str(count) + " of " + str(len(md_keys_copy)) + " complete.")
            count = count + 1
            if count % (len(md_keys_copy)/100) == 0:
                percent = percent + 1
                print(str(percent) + " percent complete...")

            if "call_sites" in md[fn] and "lang" in md[fn]:
                call_sites_copy = md[fn]["call_sites"]
                for cs in call_sites_copy:
                    if cs in md:
                        if "lang" in md[cs]:
                            if md[cs]["lang"] != md[fn]["lang"]:

                                ### transfer points
                                # Creates a transfer points metadata field to an already seen function
                                if "transfer_points" not in md[fn]:
                                    md[fn]["transfer_points"] = [cs]

                                # Appends metadata to an already seen transfer points list for a function
                                else:
                                    tmp = md[fn]["transfer_points"]
                                    tmp_set = set(tmp)
                                    tmp_set = tmp_set.union(set([cs]))
                                    md[fn]["transfer_points"] = list(tmp_set)

                                ### visitor points 
                                # Creates a visitor points metadata field to an already seen function
                                if "visitor_points" not in md[cs]:
                                    md[cs]["visitor_points"] = [fn]

                                # Appends metadata to an already seen transfer points list for a function
                                else:
                                    tmp = md[cs]["visitor_points"]
                                    tmp_set = set(tmp)
                                    tmp_set = tmp_set.union(set([fn]))
                                    md[cs]["visitor_points"] = list(tmp_set)
                        else:
                            print("Error: Call site " + str(cs) + " has no language information.") 
                    else:
                        # TODO: Objdump called functions plus offsets, need to add it as a function or remove it from the call sites list
                        # Temporary solution: just remove functions with offsets from call sites list
                        if '+0x' in str(cs):
                            print("Removing " + str(cs) + " as a call site...") 
                            md[fn]["call_sites"].remove(cs)
                        else:
                            # Temporary solution 2: find plt calls
                            found = False
                            if "@plt" in cs:
                                stripped_name = str(cs).split('@')[0]

                                # If the plt function exists in the metadata, replace the plt call site with the real function
                                for newcs in md.keys():
                                    if newcs.startswith(stripped_name) and not found:
                                        md[fn]["call_sites"].remove(cs)
                                        md[fn]["call_sites"].append(newcs)

                                        # Same as above but with newcs instead of cs
                                        if "lang" in md[newcs]:
                                            if md[newcs]["lang"] != md[fn]["lang"]:

                                                ### transfer points
                                                # Creates a transfer points metadata field to an already seen function
                                                if "transfer_points" not in md[fn]:
                                                    md[fn]["transfer_points"] = [newcs]

                                                # Appends metadata to an already seen transfer points list for a function
                                                else:
                                                    tmp = md[fn]["transfer_points"]
                                                    tmp_set = set(tmp)
                                                    tmp_set = tmp_set.union(set([newcs]))
                                                    md[fn]["transfer_points"] = list(tmp_set)

                                                ### visitor points 
                                                # Creates a visitor points metadata field to an already seen function
                                                if "visitor_points" not in md[newcs]:
                                                    md[newcs]["visitor_points"] = [fn]

                                                # Appends metadata to an already seen transfer points list for a function
                                                else:
                                                    tmp = md[newcs]["visitor_points"]
                                                    tmp_set = set(tmp)
                                                    tmp_set = tmp_set.union(set([fn]))
                                                    md[newcs]["visitor_points"] = list(tmp_set)

                                        else:
                                            print("Error: Call site " + str(newcs) + " has no language information.") 

                                        found = True

                                # If the plt function is not in the metadata, add the plt call site to the metadata 
                                if not found:
                                    found = True

                                    if "_Z" in cs:
                                        t = "unknown"
                                        l = "c++"
                                    else:
                                        t = "external"
                                        l = "c"

                                    md[cs] = {
                                            "addr": "unknown",
                                            "type": t,
                                            "lang": l,
                                            "call_sites": [],
                                            "num_indirect_calls": float(0),
                                            "num_dynamic_calls": float(0),
                                            }

                                    if "lang" in md[cs]:
                                        if md[cs]["lang"] != md[fn]["lang"]:

                                            ### transfer points
                                            # Creates a transfer points metadata field to an already seen function
                                            if "transfer_points" not in md[fn]:
                                                md[fn]["transfer_points"] = [cs]

                                            # Appends metadata to an already seen transfer points list for a function
                                            else:
                                                tmp = md[fn]["transfer_points"]
                                                tmp_set = set(tmp)
                                                tmp_set = tmp_set.union(set([cs]))
                                                md[fn]["transfer_points"] = list(tmp_set)

                                            ### visitor points 
                                            # Creates a visitor points metadata field to an already seen function
                                            if "visitor_points" not in md[cs]:
                                                md[cs]["visitor_points"] = [fn]

                                            # Appends metadata to an already seen transfer points list for a function
                                            else:
                                                tmp = md[cs]["visitor_points"]
                                                tmp_set = set(tmp)
                                                tmp_set = tmp_set.union(set([fn]))
                                                md[cs]["visitor_points"] = list(tmp_set)

                            if not found:
                                print("Error: Call site " + str(cs) + " does not exist in metadata.") 
                                print("...removing as a call site...")
                                md[fn]["call_sites"].remove(cs)
            else:
                print("Error: Function " + str(fn) + " either has no call sites field or no language information field.") 

        print("Adding size of call sites, transfer points, and visitor points lists...")
        for fn in md.keys():
            if "call_sites" in md[fn]:
                md[fn]["num_call_sites"] = len(md[fn]["call_sites"])
            else:
                md[fn]["call_sites"] = []
                md[fn]["num_call_sites"] = float(0)

            if "transfer_points" in md[fn]:
                md[fn]["num_transfer_points"] = len(md[fn]["transfer_points"])
            else:
                md[fn]["transfer_points"] = []
                md[fn]["num_transfer_points"] = float(0)

            if "visitor_points" in md[fn]:
                md[fn]["num_visitor_points"] = len(md[fn]["visitor_points"])
            else:
                md[fn]["visitor_points"] = []
                md[fn]["num_visitor_points"] = float(0)

        print("Saving metadata with transfer and visitor points...")
        f = open("output/metadata_with_tps.json", "w")
        json.dump(md, f, indent=4)

def get_invocation_points():
    print("Opening metadata to find invocation points...")
    with open("output/metadata_with_tps.json") as mj:
        md = json.load(mj)

        # For each function, get a list of which functions call other functions 
        print("Iterating through metadata functions...")
        for fn in md.keys():

            for cs in md[fn]["call_sites"]:

                if cs in md:

                    ### invocation points
                    # Creates a invocation points metadata field to an already seen function
                    if "invocation_points" not in md[cs]:
                        md[cs]["invocation_points"] = [fn]

                    # Appends metadata to an already seen transfer points list for a function
                    else:
                        tmp = md[cs]["invocation_points"]
                        tmp_set = set(tmp)
                        tmp_set = tmp_set.union(set([fn]))
                        md[cs]["invocation_points"] = list(tmp_set)
                else:
                    print("Error: " + str(cs) + " does not exist in the metadata.")

        for fn in md.keys():
            if "invocation_points" not in md[fn]:
                md[fn]["invocation_points"] = []

            md[fn]["num_invocations"] = float(len(md[fn]["invocation_points"]))

        print("Saving metadata with invocation points...")
        f = open("output/metadata_with_invos.json", "w")
        json.dump(md, f, indent=4)


def generate_cdfs():
    print("Setting plot params...")
    plt.style.use('ggplot')

    plt.rcParams['figure.titlesize'] = 20
    plt.rcParams['axes.labelsize'] = 16
    plt.rcParams['axes.titlesize'] = 16
    plt.rcParams['xtick.labelsize'] = 14
    plt.rcParams['ytick.labelsize'] = 14
    plt.rcParams['legend.fontsize'] = 16
    plt.rcParams['axes.grid'] = 'true'
    plt.rcParams['grid.color'] = '0.45'
    plt.rcParams['axes.facecolor'] = '0.95'

    # with_invos is the json metadata file with the most data
    print("Loading metadata to generate cdfs...")
    with open("output/metadata_with_invos.json") as mj:
        md = json.load(mj)

        ### CDFs
        ## Make a CDF for number of indirect calls
        both_indirs = []
        rust_indirs = []
        c_indirs = []

        ## Make a CDF for number of dynamic calls
        both_dynamics = []
        rust_dynamics = []
        c_dynamics = []


        ## Make a CDF for number of call sites
        both_cs = []
        rust_cs = []
        c_cs = []

        ## Make a CDF for number of visitor points
        both_vps = []
        rust_vps = []
        c_vps = []

        ## Make a CDF for number of invocation points 
        both_invos = []
        rust_invos = []
        c_invos = []

        ## Make a CDF for number of transfer points
        both_tps = []
        rust_tps = []
        c_tps = []

        ### Table values
        ## Table value of total number of functions
        both_fns = 0
        rust_fns = 0
        c_fns = 0

        ## Table value of total number of invocations
        both_total_indirs = 0
        rust_total_indirs = 0
        c_total_indirs = 0

        ## Table value of total number of invocations
        both_total_dynamics = 0
        rust_total_dynamics = 0
        c_total_dynamics = 0

        ## Table value of total number of invocations
        both_total_cs = 0
        rust_total_cs = 0
        c_total_cs = 0

        ## Table value of total number of invocations
        both_total_vps = 0
        rust_total_vps = 0
        c_total_vps = 0

        ## Table value of total number of invocations
        both_total_invos = 0
        rust_total_invos = 0
        c_total_invos = 0

        ## Table value of total number of invocations
        both_total_tps = 0
        rust_total_tps = 0
        c_total_tps = 0

        ## Table value of total number of closures
        rust_closures = 0

        ## Table value of total number of monomorphized functions
        rust_monos = 0

        ## Largest Degree Call sites 
        both_top_cs = {
                "first": {
                    "name": "unknown",
                    "num": 0
                    },
                "second": {
                    "name": "unknown",
                    "num": 0
                    },
                "third": {
                    "name": "unknown",
                    "num": 0
                    },
                }
        rust_top_cs = {
                "first": {
                    "name": "unknown",
                    "num": 0
                    },
                "second": {
                    "name": "unknown",
                    "num": 0
                    },
                "third": {
                    "name": "unknown",
                    "num": 0
                    },
                }
        c_top_cs = {
                "first": {
                    "name": "unknown",
                    "num": 0
                    },
                "second": {
                    "name": "unknown",
                    "num": 0
                    },
                "third": {
                    "name": "unknown",
                    "num": 0
                    },
                }

        ## Largest Degree Invocations 
        both_top_invos = {
                "first": {
                    "name": "unknown",
                    "num": 0
                    },
                "second": {
                    "name": "unknown",
                    "num": 0
                    },
                "third": {
                    "name": "unknown",
                    "num": 0
                    },
                }
        rust_top_invos = {
                "first": {
                    "name": "unknown",
                    "num": 0
                    },
                "second": {
                    "name": "unknown",
                    "num": 0
                    },
                "third": {
                    "name": "unknown",
                    "num": 0
                    },
                }
        c_top_invos = {
                "first": {
                    "name": "unknown",
                    "num": 0
                    },
                "second": {
                    "name": "unknown",
                    "num": 0
                    },
                "third": {
                    "name": "unknown",
                    "num": 0
                    },
                }

        ## Largest Degree Transfer Points 
        both_top_tps = {
                "first": {
                    "name": "unknown",
                    "num": 0
                    },
                "second": {
                    "name": "unknown",
                    "num": 0
                    },
                "third": {
                    "name": "unknown",
                    "num": 0
                    },
                }
        rust_top_tps = {
                "first": {
                    "name": "unknown",
                    "num": 0
                    },
                "second": {
                    "name": "unknown",
                    "num": 0
                    },
                "third": {
                    "name": "unknown",
                    "num": 0
                    },
                }
        c_top_tps = {
                "first": {
                    "name": "unknown",
                    "num": 0
                    },
                "second": {
                    "name": "unknown",
                    "num": 0
                    },
                "third": {
                    "name": "unknown",
                    "num": 0
                    },
                }

        ## Largest Degree Visitor Points 
        both_top_vps = {
                "first": {
                    "name": "unknown",
                    "num": 0
                    },
                "second": {
                    "name": "unknown",
                    "num": 0
                    },
                "third": {
                    "name": "unknown",
                    "num": 0
                    },
                }
        rust_top_vps = {
                "first": {
                    "name": "unknown",
                    "num": 0
                    },
                "second": {
                    "name": "unknown",
                    "num": 0
                    },
                "third": {
                    "name": "unknown",
                    "num": 0
                    },
                }
        c_top_vps = {
                "first": {
                    "name": "unknown",
                    "num": 0
                    },
                "second": {
                    "name": "unknown",
                    "num": 0
                    },
                "third": {
                    "name": "unknown",
                    "num": 0
                    },
                }


        print("Looping through metadata to collect graph data...")
        for name in md.keys():

            if md[name]["lang"] == "rust":
                try: 
                    rust_indirs.append(float(md[name]["num_indirect_calls"]))
                    rust_dynamics.append(float(md[name]["num_dynamic_calls"]))
                    rust_cs.append(float(md[name]["num_call_sites"]))
                    rust_tps.append(float(md[name]["num_transfer_points"]))
                    rust_vps.append(float(md[name]["num_visitor_points"]))
                    rust_invos.append(float(md[name]["num_invocations"]))

                    rust_fns = rust_fns + 1

                    rust_total_indirs = rust_total_indirs + float(md[name]["num_indirect_calls"])
                    rust_total_dynamics = rust_total_dynamics + float(md[name]["num_dynamic_calls"])
                    rust_total_cs = rust_total_cs + float(md[name]["num_call_sites"])
                    rust_total_tps = rust_total_tps + float(md[name]["num_transfer_points"])
                    rust_total_vps = rust_total_vps + float(md[name]["num_visitor_points"])
                    rust_total_invos = rust_total_invos + float(md[name]["num_invocations"])

                    #if md[name]["type"] == "closure":
                        #rust_closures = rust_closures + 1
                    #if md[name]["type"] == "static":
                        #rust_monos = rust_monos + 1
                    if "_R" in name:
                        mangled = False
                        if sum(1 for c in name if c.isupper()) > 1:
                            mangled = True

                        if mangled:
                            if "CN" in name:
                                rust_closures = rust_closures + 1
                            elif "IN" in name:
                                rust_monos = rust_monos + 1
                            elif "X" in name:
                                rust_monos = rust_monos + 1
                            elif "M" in name:
                                rust_monos = rust_monos + 1

                    ## Check top call sites
                    if float(md[name]["num_call_sites"]) > float(rust_top_cs["first"]["num"]):
                        #print("Found new top leader")
                        #print(md[name]["num_call_sites"])
                        #print(rust_top_cs)

                        # Get tmps
                        tmp1 = {
                                "name": rust_top_cs["first"]["name"],
                                "num": rust_top_cs["first"]["num"],
                                }
                        tmp2 = {
                                "name": rust_top_cs["second"]["name"],
                                "num": rust_top_cs["second"]["num"],
                                }

                        #print(tmp1)
                        #print(tmp2)

                        # Set the new leader
                        rust_top_cs["first"]["name"] = str(name)
                        rust_top_cs["first"]["num"] = float(md[name]["num_call_sites"])

                        #print(tmp1)
                        #print(tmp2)

                        # Move down
                        rust_top_cs["second"] = tmp1
                        rust_top_cs["third"] = tmp2

                    elif float(md[name]["num_call_sites"]) > float(rust_top_cs["second"]["num"]):
                        # Get tmps
                        tmp2 = {
                                "name": rust_top_cs["second"]["name"],
                                "num": rust_top_cs["second"]["num"],
                                }

                        # Set the new leader
                        rust_top_cs["second"]["name"] = str(name)
                        rust_top_cs["second"]["num"] = float(md[name]["num_call_sites"])

                        # Move down
                        rust_top_cs["third"] = tmp2

                    elif float(md[name]["num_call_sites"]) > float(rust_top_cs["third"]["num"]):
                        # Set the new leader
                        rust_top_cs["third"]["name"] = str(name)
                        rust_top_cs["third"]["num"] = float(md[name]["num_call_sites"])

                    ## Check top invocations 
                    if float(md[name]["num_invocations"]) > float(rust_top_invos["first"]["num"]):
                        # Get tmps
                        tmp1 = {
                                "name": rust_top_invos["first"]["name"],
                                "num": rust_top_invos["first"]["num"],
                                }
                        tmp2 = {
                                "name": rust_top_invos["second"]["name"],
                                "num": rust_top_invos["second"]["num"],
                                }

                        # Set the new leader
                        rust_top_invos["first"]["name"] = str(name)
                        rust_top_invos["first"]["num"] = float(md[name]["num_invocations"])

                        # Move down
                        rust_top_invos["second"] = tmp1
                        rust_top_invos["third"] = tmp2

                    elif float(md[name]["num_invocations"]) > float(rust_top_invos["second"]["num"]):
                        # Get tmps
                        tmp2 = rust_top_invos["second"]
                        tmp2 = {
                                "name": rust_top_invos["second"]["name"],
                                "num": rust_top_invos["second"]["num"],
                                }

                        # Set the new leader
                        rust_top_invos["second"]["name"] = str(name)
                        rust_top_invos["second"]["num"] = float(md[name]["num_invocations"])

                        # Move down
                        rust_top_invos["third"] = tmp2

                    elif float(md[name]["num_invocations"]) > float(rust_top_invos["third"]["num"]):
                        # Set the new leader
                        rust_top_invos["third"]["name"] = str(name)
                        rust_top_invos["third"]["num"] = float(md[name]["num_invocations"])

                    ## Check top Transfer Points
                    if float(md[name]["num_transfer_points"]) > float(rust_top_tps["first"]["num"]):
                        # Get tmps
                        tmp1 = {
                                "name": rust_top_tps["first"]["name"],
                                "num": rust_top_tps["first"]["num"],
                                }
                        tmp2 = {
                                "name": rust_top_tps["second"]["name"],
                                "num": rust_top_tps["second"]["num"],
                                }

                        # Set the new leader
                        rust_top_tps["first"]["name"] = str(name)
                        rust_top_tps["first"]["num"] = float(md[name]["num_transfer_points"])

                        # Move down
                        rust_top_tps["second"] = tmp1
                        rust_top_tps["third"] = tmp2

                    elif float(md[name]["num_transfer_points"]) > float(rust_top_tps["second"]["num"]):
                        # Get tmps
                        tmp2 = rust_top_tps["second"]
                        tmp2 = {
                                "name": rust_top_tps["second"]["name"],
                                "num": rust_top_tps["second"]["num"],
                                }

                        # Set the new leader
                        rust_top_tps["second"]["name"] = str(name)
                        rust_top_tps["second"]["num"] = float(md[name]["num_transfer_points"])

                        # Move down
                        rust_top_tps["third"] = tmp2

                    elif float(md[name]["num_transfer_points"]) > float(rust_top_tps["third"]["num"]):
                        # Set the new leader
                        rust_top_tps["third"]["name"] = str(name)
                        rust_top_tps["third"]["num"] = float(md[name]["num_transfer_points"])

                    ## Check top invocations 
                    if float(md[name]["num_visitor_points"]) > float(rust_top_vps["first"]["num"]):
                        # Get tmps
                        tmp1 = {
                                "name": rust_top_vps["first"]["name"],
                                "num": rust_top_vps["first"]["num"],
                                }
                        tmp2 = {
                                "name": rust_top_vps["second"]["name"],
                                "num": rust_top_vps["second"]["num"],
                                }

                        # Set the new leader
                        rust_top_vps["first"]["name"] = str(name)
                        rust_top_vps["first"]["num"] = float(md[name]["num_visitor_points"])

                        # Move down
                        rust_top_vps["second"] = tmp1
                        rust_top_vps["third"] = tmp2

                    elif float(md[name]["num_visitor_points"]) > float(rust_top_vps["second"]["num"]):
                        # Get tmps
                        tmp2 = {
                                "name": rust_top_vps["second"]["name"],
                                "num": rust_top_vps["second"]["num"],
                                }

                        # Set the new leader
                        rust_top_vps["second"]["name"] = str(name)
                        rust_top_vps["second"]["num"] = float(md[name]["num_visitor_points"])

                        # Move down
                        rust_top_vps["third"] = tmp2

                    elif float(md[name]["num_visitor_points"]) > float(rust_top_vps["third"]["num"]):
                        # Set the new leader
                        rust_top_vps["third"]["name"] = str(name)
                        rust_top_vps["third"]["num"] = float(md[name]["num_visitor_points"])

                except Exception as e:
                    print(e)

            #elif md[name]["lang"] == "c" or md[name]["lang"] == "c++":
            else:
                try: 
                    c_indirs.append(float(md[name]["num_indirect_calls"]))
                    c_dynamics.append(float(md[name]["num_dynamic_calls"]))
                    c_cs.append(float(md[name]["num_call_sites"]))
                    c_tps.append(float(md[name]["num_transfer_points"]))
                    c_vps.append(float(md[name]["num_visitor_points"]))
                    c_invos.append(float(md[name]["num_invocations"]))

                    c_fns = c_fns + 1

                    c_total_indirs = c_total_indirs + float(md[name]["num_indirect_calls"])
                    c_total_dynamics = c_total_dynamics + float(md[name]["num_dynamic_calls"])
                    c_total_cs = c_total_cs + float(md[name]["num_call_sites"])
                    c_total_tps = c_total_tps + float(md[name]["num_transfer_points"])
                    c_total_vps = c_total_vps + float(md[name]["num_visitor_points"])
                    c_total_invos = c_total_invos + float(md[name]["num_invocations"])

                    ## Check top call sites
                    if float(md[name]["num_call_sites"]) > float(c_top_cs["first"]["num"]):
                        # Get tmps
                        tmp1 = {
                                "name": c_top_cs["first"]["name"],
                                "num": c_top_cs["first"]["num"],
                                }
                        tmp2 = {
                                "name": c_top_cs["second"]["name"],
                                "num": c_top_cs["second"]["num"],
                                }

                        # Set the new leader
                        c_top_cs["first"]["name"] = str(name)
                        c_top_cs["first"]["num"] = float(md[name]["num_call_sites"])

                        # Move down
                        c_top_cs["second"] = tmp1
                        c_top_cs["third"] = tmp2

                    elif float(md[name]["num_call_sites"]) > float(c_top_cs["second"]["num"]):
                        # Get tmps
                        tmp2 = {
                                "name": c_top_cs["second"]["name"],
                                "num": c_top_cs["second"]["num"],
                                }

                        # Set the new leader
                        c_top_cs["second"]["name"] = str(name)
                        c_top_cs["second"]["num"] = float(md[name]["num_call_sites"])

                        # Move down
                        c_top_cs["third"] = tmp2

                    elif float(md[name]["num_call_sites"]) > float(c_top_cs["third"]["num"]):
                        # Set the new leader
                        c_top_cs["third"]["name"] = str(name)
                        c_top_cs["third"]["num"] = float(md[name]["num_call_sites"])

                    ## Check top invocations 
                    if float(md[name]["num_invocations"]) > float(c_top_invos["first"]["num"]):
                        # Get tmps
                        tmp1 = {
                                "name": c_top_invos["first"]["name"],
                                "num": c_top_invos["first"]["num"],
                                }
                        tmp2 = {
                                "name": c_top_invos["second"]["name"],
                                "num": c_top_invos["second"]["num"],
                                }

                        # Set the new leader
                        c_top_invos["first"]["name"] = str(name)
                        c_top_invos["first"]["num"] = float(md[name]["num_invocations"])

                        # Move down
                        c_top_invos["second"] = tmp1
                        c_top_invos["third"] = tmp2

                    elif float(md[name]["num_invocations"]) > float(c_top_invos["second"]["num"]):
                        # Get tmps
                        tmp2 = {
                                "name": c_top_invos["second"]["name"],
                                "num": c_top_invos["second"]["num"],
                                }

                        # Set the new leader
                        c_top_invos["second"]["name"] = str(name)
                        c_top_invos["second"]["num"] = float(md[name]["num_invocations"])

                        # Move down
                        c_top_invos["third"] = tmp2

                    elif float(md[name]["num_invocations"]) > float(c_top_invos["third"]["num"]):
                        # Set the new leader
                        c_top_invos["third"]["name"] = str(name)
                        c_top_invos["third"]["num"] = float(md[name]["num_invocations"])

                    ## Check top Transfer Points
                    if float(md[name]["num_transfer_points"]) > float(c_top_tps["first"]["num"]):
                        # Get tmps
                        tmp1 = {
                                "name": c_top_tps["first"]["name"],
                                "num": c_top_tps["first"]["num"],
                                }
                        tmp2 = {
                                "name": c_top_tps["second"]["name"],
                                "num": c_top_tps["second"]["num"],
                                }

                        # Set the new leader
                        c_top_tps["first"]["name"] = str(name)
                        c_top_tps["first"]["num"] = float(md[name]["num_transfer_points"])

                        # Move down
                        c_top_tps["second"] = tmp1
                        c_top_tps["third"] = tmp2

                    elif float(md[name]["num_transfer_points"]) > float(c_top_tps["second"]["num"]):
                        # Get tmps
                        tmp2 = {
                                "name": c_top_tps["second"]["name"],
                                "num": c_top_tps["second"]["num"],
                                }

                        # Set the new leader
                        c_top_tps["second"]["name"] = str(name)
                        c_top_tps["second"]["num"] = float(md[name]["num_transfer_points"])

                        # Move down
                        c_top_tps["third"] = tmp2

                    elif float(md[name]["num_transfer_points"]) > float(c_top_tps["third"]["num"]):
                        # Set the new leader
                        c_top_tps["third"]["name"] = str(name)
                        c_top_tps["third"]["num"] = float(md[name]["num_transfer_points"])

                    ## Check top invocations 
                    if float(md[name]["num_visitor_points"]) > float(c_top_vps["first"]["num"]):
                        # Get tmps
                        tmp1 = {
                                "name": c_top_vps["first"]["name"],
                                "num": c_top_vps["first"]["num"],
                                }
                        tmp2 = {
                                "name": c_top_vps["second"]["name"],
                                "num": c_top_vps["second"]["num"],
                                }

                        # Set the new leader
                        c_top_vps["first"]["name"] = str(name)
                        c_top_vps["first"]["num"] = float(md[name]["num_visitor_points"])

                        # Move down
                        c_top_vps["second"] = tmp1
                        c_top_vps["third"] = tmp2

                    elif float(md[name]["num_visitor_points"]) > float(c_top_vps["second"]["num"]):
                        # Get tmps
                        tmp2 = {
                                "name": c_top_vps["second"]["name"],
                                "num": c_top_vps["second"]["num"],
                                }

                        # Set the new leader
                        c_top_vps["second"]["name"] = str(name)
                        c_top_vps["second"]["num"] = float(md[name]["num_visitor_points"])

                        # Move down
                        c_top_vps["third"] = tmp2

                    elif float(md[name]["num_visitor_points"]) > float(c_top_vps["third"]["num"]):
                        # Set the new leader
                        c_top_vps["third"]["name"] = str(name)
                        c_top_vps["third"]["num"] = float(md[name]["num_visitor_points"])

                except Exception as e:
                    print(e)

            try: 
                both_indirs.append(float(md[name]["num_indirect_calls"]))
                both_dynamics.append(float(md[name]["num_dynamic_calls"]))
                both_cs.append(float(md[name]["num_call_sites"]))
                both_tps.append(float(md[name]["num_transfer_points"]))
                both_vps.append(float(md[name]["num_visitor_points"]))
                both_invos.append(float(md[name]["num_invocations"]))

                both_fns = both_fns + 1

                both_total_indirs = both_total_indirs + float(md[name]["num_indirect_calls"])
                both_total_dynamics = both_total_dynamics + float(md[name]["num_dynamic_calls"])
                both_total_cs = both_total_cs + float(md[name]["num_call_sites"])
                both_total_tps = both_total_tps + float(md[name]["num_transfer_points"])
                both_total_vps = both_total_vps + float(md[name]["num_visitor_points"])
                both_total_invos = both_total_invos + float(md[name]["num_invocations"])

                ## Check top call sites
                if float(md[name]["num_call_sites"]) > float(both_top_cs["first"]["num"]):
                    # Get tmps
                    tmp1 = both_top_cs["first"]
                    tmp2 = both_top_cs["second"]
                    tmp1 = {
                            "name": both_top_cs["first"]["name"],
                            "num": both_top_cs["first"]["num"],
                            }
                    tmp2 = {
                            "name": both_top_cs["second"]["name"],
                            "num": both_top_cs["second"]["num"],
                            }

                    # Set the new leader
                    both_top_cs["first"]["name"] = str(name)
                    both_top_cs["first"]["num"] = float(md[name]["num_call_sites"])

                    # Move down
                    both_top_cs["second"] = tmp1
                    both_top_cs["third"] = tmp2

                elif float(md[name]["num_call_sites"]) > float(both_top_cs["second"]["num"]):
                    # Get tmps
                    tmp2 = both_top_cs["second"]
                    tmp2 = {
                            "name": both_top_cs["second"]["name"],
                            "num": both_top_cs["second"]["num"],
                            }

                    # Set the new leader
                    both_top_cs["second"]["name"] = str(name)
                    both_top_cs["second"]["num"] = float(md[name]["num_call_sites"])

                    # Move down
                    both_top_cs["third"] = tmp2

                elif float(md[name]["num_call_sites"]) > float(both_top_cs["third"]["num"]):
                    # Set the new leader
                    both_top_cs["third"]["name"] = str(name)
                    both_top_cs["third"]["num"] = float(md[name]["num_call_sites"])

                ## Check top invocations 
                if float(md[name]["num_invocations"]) > float(both_top_invos["first"]["num"]):
                    # Get tmps
                    tmp1 = {
                            "name": both_top_invos["first"]["name"],
                            "num": both_top_invos["first"]["num"],
                            }
                    tmp2 = {
                            "name": both_top_invos["second"]["name"],
                            "num": both_top_invos["second"]["num"],
                            }

                    # Set the new leader
                    both_top_invos["first"]["name"] = str(name)
                    both_top_invos["first"]["num"] = float(md[name]["num_invocations"])

                    # Move down
                    both_top_invos["second"] = tmp1
                    both_top_invos["third"] = tmp2

                elif float(md[name]["num_invocations"]) > float(both_top_invos["second"]["num"]):
                    # Get tmps
                    tmp2 = {
                            "name": both_top_invos["second"]["name"],
                            "num": both_top_invos["second"]["num"],
                            }

                    # Set the new leader
                    both_top_invos["second"]["name"] = str(name)
                    both_top_invos["second"]["num"] = float(md[name]["num_invocations"])

                    # Move down
                    both_top_invos["third"] = tmp2

                elif float(md[name]["num_invocations"]) > float(both_top_invos["third"]["num"]):
                    # Set the new leader
                    both_top_invos["third"]["name"] = str(name)
                    both_top_invos["third"]["num"] = float(md[name]["num_invocations"])

                ## Check top Transfer Points
                if float(md[name]["num_transfer_points"]) > float(both_top_tps["first"]["num"]):
                    # Get tmps
                    tmp1 = {
                            "name": both_top_tps["first"]["name"],
                            "num": both_top_tps["first"]["num"],
                            }
                    tmp2 = {
                            "name": both_top_tps["second"]["name"],
                            "num": both_top_tps["second"]["num"],
                            }

                    # Set the new leader
                    both_top_tps["first"]["name"] = str(name)
                    both_top_tps["first"]["num"] = float(md[name]["num_transfer_points"])

                    # Move down
                    both_top_tps["second"] = tmp1
                    both_top_tps["third"] = tmp2

                elif float(md[name]["num_transfer_points"]) > float(both_top_tps["second"]["num"]):
                    # Get tmps
                    tmp2 = {
                            "name": both_top_tps["second"]["name"],
                            "num": both_top_tps["second"]["num"],
                            }

                    # Set the new leader
                    both_top_tps["second"]["name"] = str(name)
                    both_top_tps["second"]["num"] = float(md[name]["num_transfer_points"])

                    # Move down
                    both_top_tps["third"] = tmp2

                elif float(md[name]["num_transfer_points"]) > float(both_top_tps["third"]["num"]):
                    # Set the new leader
                    both_top_tps["third"]["name"] = str(name)
                    both_top_tps["third"]["num"] = float(md[name]["num_transfer_points"])

                ## Check top invocations 
                if float(md[name]["num_visitor_points"]) > float(both_top_vps["first"]["num"]):
                    # Get tmps
                    tmp1 = {
                            "name": both_top_vps["first"]["name"],
                            "num": both_top_vps["first"]["num"],
                            }
                    tmp2 = {
                            "name": both_top_vps["second"]["name"],
                            "num": both_top_vps["second"]["num"],
                            }

                    # Set the new leader
                    both_top_vps["first"]["name"] = str(name)
                    both_top_vps["first"]["num"] = float(md[name]["num_visitor_points"])

                    # Move down
                    both_top_vps["second"] = tmp1
                    both_top_vps["third"] = tmp2

                elif float(md[name]["num_visitor_points"]) > float(both_top_vps["second"]["num"]):
                    # Get tmps
                    tmp2 = both_top_vps["second"]

                    # Set the new leader
                    both_top_vps["second"]["name"] = str(name)
                    both_top_vps["second"]["num"] = float(md[name]["num_visitor_points"])

                    # Move down
                    tmp2 = {
                            "name": both_top_vps["second"]["name"],
                            "num": both_top_vps["second"]["num"],
                            }

                elif float(md[name]["num_visitor_points"]) > float(both_top_vps["third"]["num"]):
                    # Set the new leader
                    both_top_vps["third"]["name"] = str(name)
                    both_top_vps["third"]["num"] = float(md[name]["num_visitor_points"])

            except Exception as e:
                print(e)

        ### Print table metrics
        ## Number of Functions
        print("Total functions: ")
        print("Rust: " + str(rust_fns))
        print("C/C++: " + str(c_fns))
        print("Both: " + str(both_fns))

        ## Number of Indirections
        print("Total Indirect Calls: ")
        print("Rust: " + str(rust_total_indirs))
        print("C/C++: " + str(c_total_indirs))
        print("Both: " + str(both_total_indirs))

        ## Number of Indirections
        print("Total Dynamic Calls: ")
        print("Rust: " + str(rust_total_dynamics))
        print("C/C++: " + str(c_total_dynamics))
        print("Both: " + str(both_total_dynamics))

        ## Number of Call Sites
        print("Total Call Sites: ")
        print("Rust: " + str(rust_total_cs))
        print("C/C++: " + str(c_total_cs))
        print("Both: " + str(both_total_cs))

        ## Number of Transfer Points 
        print("Total Transfer Points: ")
        print("Rust: " + str(rust_total_tps))
        print("C/C++: " + str(c_total_tps))
        print("Both: " + str(both_total_tps))

        ## Number of Visitor Points 
        print("Total Visitor Points: ")
        print("Rust: " + str(rust_total_vps))
        print("C/C++: " + str(c_total_vps))
        print("Both: " + str(both_total_vps))

        ## Number of Invocations 
        print("Total Invocations: ")
        print("Rust: " + str(rust_total_invos))
        print("C/C++: " + str(c_total_invos))
        print("Both: " + str(both_total_invos))

        ## Number of Rust closures 
        print("Total Closures: ")
        print("Rust: " + str(rust_closures))

        ## Number of Rust monophorphized functions 
        print("Total Monomorphized Functions: ")
        print("Rust: " + str(rust_monos))

        ### Print Top contenders
        ## Top Call Sites
        print("Top Call Sites:")
        print("Both: " + str(both_top_cs))
        print("Rust: " + str(rust_top_cs))
        print("C/C++: " + str(c_top_cs))

        ## Top Invocations 
        print("Top Invocations:")
        print("Both: " + str(both_top_invos))
        print("Rust: " + str(rust_top_invos))
        print("C/C++: " + str(c_top_invos))

        ## Top Transfer Points 
        print("Top Transfer Points:")
        print("Both: " + str(both_top_tps))
        print("Rust: " + str(rust_top_tps))
        print("C/C++: " + str(c_top_tps))

        ## Top Visitor Points 
        print("Top Visitor Points:")
        print("Both: " + str(both_top_vps))
        print("Rust: " + str(rust_top_vps))
        print("C/C++: " + str(c_top_vps))

        ### Make a CDF for number of indirect calls
        rust_x = np.sort(np.array(rust_indirs))
        rust_y = np.arange(1, len(rust_x)+1)/len(rust_x)

        c_x = np.sort(np.array(c_indirs))
        c_y = np.arange(1, len(c_x)+1)/len(c_x)

        both_x = np.sort(np.array(both_indirs))
        both_y = np.arange(1, len(both_x)+1)/len(both_x)

        print("Generating CDF for indirect function calls...")
        print(both_y)
        cdf_plt = plt.figure()

        # Graph labels
        plt.title("Number of Indirect Function Calls")
        plt.xlabel("Number of Indirect Function Calls")
        plt.ylabel("Cumulative Distribution Function (CDF)")

        #plt.axis([0, max(both_x), 0, 1])
        plt.axis([0, 10, 0.9, 1])

        # Grayscale
        #plt.plot(both_x, both_y, label='All', marker='^', color='0.6', linestyle='-', markevery=len(both_x)/10000000)
        #plt.plot(rust_x, rust_y, label='Rust', marker='o', color='0.35', linestyle='-', markevery=len(rust_x)/200000)
        #plt.plot(c_x, c_y, label='C/C++', marker='s', color='0', linestyle='-', markevery=len(c_x)/10000000)

        # Color
        plt.plot(both_x, both_y, label='All', marker='^', color='0', linestyle='-', markevery=len(both_x)/10000000)
        plt.plot(rust_x, rust_y, label='Rust', marker='o', color='red', linestyle='-', markevery=len(rust_x)/200000)
        plt.plot(c_x, c_y, label='C/C++', marker='s', color='blue', linestyle='-', markevery=len(c_x)/10000000)

        # Generate and save graph
        #plt.grid(True)
        plt.grid(True, color='0.45')
        plt.plot()
        plt.show()
        plt.legend(loc='upper center',bbox_to_anchor=(0.5, -0.15),shadow=True, ncol=3)
        print("Saving indirs...")
        cdf_plt.savefig("output/graphs/indirs.pdf", bbox_inches='tight')


        ### Make a CDF for number of dynamic calls
        rust_x = np.sort(np.array(rust_dynamics))
        rust_y = np.arange(1, len(rust_x)+1)/len(rust_x)

        c_x = np.sort(np.array(c_dynamics))
        c_y = np.arange(1, len(c_x)+1)/len(c_x)

        both_x = np.sort(np.array(both_dynamics))
        both_y = np.arange(1, len(both_x)+1)/len(both_x)

        print("Generating CDF for dynamic function calls...")
        cdf_plt = plt.figure()

        # Graph labels
        plt.title("Number of Dynamic Function Calls")
        plt.xlabel("Number of Dynamic Function Calls")
        plt.ylabel("Cumulative Distribution Function (CDF)")

        #plt.axis([0, max(both_x), 0.9, 1])
        plt.axis([0, 20, 0.85, 1])

        #plt.plot(both_x, both_y, label='All', marker='^', color='0.6', linestyle='-', markevery=len(both_x)/5000000)
        #plt.plot(rust_x, rust_y, label='Rust', marker='o', color='0.35', linestyle='-', markevery=len(rust_x)/200000)
        #plt.plot(c_x, c_y, label='C/C++', marker='s', color='0', linestyle='-', markevery=len(c_x)/5000000)

        plt.plot(both_x, both_y, label='All', marker='^', color='0', linestyle='-', markevery=len(both_x)/5000000)
        plt.plot(rust_x, rust_y, label='Rust', marker='o', color='red', linestyle='-', markevery=len(rust_x)/200000)
        plt.plot(c_x, c_y, label='C/C++', marker='s', color='blue', linestyle='-', markevery=len(c_x)/5000000)

        # Generate and save graph
        #plt.grid(True)
        plt.grid(True, color='0.45')
        plt.plot()
        plt.legend(loc='upper center',bbox_to_anchor=(0.5, -0.15),shadow=True, ncol=3)
        print("Saving dynamics...")
        cdf_plt.savefig("output/graphs/dynamics.pdf", bbox_inches='tight')

        ### Make a CDF for number of call sites
        rust_x = np.sort(np.array(rust_cs))
        rust_y = np.arange(1, len(rust_x)+1)/len(rust_x)

        c_x = np.sort(np.array(c_cs))
        c_y = np.arange(1, len(c_x)+1)/len(c_x)

        both_x = np.sort(np.array(both_cs))
        both_y = np.arange(1, len(both_x)+1)/len(both_x)

        print("Generating CDF for number of call sites...")
        cdf_plt = plt.figure()

        # Graph labels
        plt.title("Number of Call Sites")
        plt.xlabel("Number of Call Sites")
        plt.ylabel("Cumulative Distribution Function (CDF)")

        #plt.axis([0, max(both_x), 0.9, 1])
        plt.axis([0, 50, 0.8, 1])

        #plt.plot(both_x, both_y, label='All', marker='^', color='0.6', linestyle='-', markevery=len(both_x)/10000000)
        #plt.plot(rust_x, rust_y, label='Rust', marker='o', color='0.35', linestyle='-', markevery=len(rust_x)/200000)
        #plt.plot(c_x, c_y, label='C/C++', marker='s', color='0', linestyle='-', markevery=len(c_x)/10000000)

        plt.plot(both_x, both_y, label='All', marker='^', color='0', linestyle='-', markevery=len(both_x)/10000000)
        plt.plot(rust_x, rust_y, label='Rust', marker='o', color='red', linestyle='-', markevery=len(rust_x)/200000)
        plt.plot(c_x, c_y, label='C/C++', marker='s', color='blue', linestyle='-', markevery=len(c_x)/10000000)

        # Generate and save graph
        #plt.grid(True)
        plt.grid(True, color='0.45')
        plt.plot()
        plt.legend(loc='upper center',bbox_to_anchor=(0.5, -0.15),shadow=True, ncol=3)
        print("Saving calls...")
        cdf_plt.savefig("output/graphs/calls.pdf", bbox_inches='tight')

        ### Make a CDF for number of transfer points
        rust_x = np.sort(np.array(rust_tps))
        rust_y = np.arange(1, len(rust_x)+1)/len(rust_x)

        c_x = np.sort(np.array(c_tps))
        c_y = np.arange(1, len(c_x)+1)/len(c_x)

        both_x = np.sort(np.array(both_tps))
        both_y = np.arange(1, len(both_x)+1)/len(both_x)

        print("Generating CDF for number of transfer points...")
        cdf_plt = plt.figure()

        # Graph labels
        plt.title("Number of Transfer Points")
        plt.xlabel("Number of Transfer Points")
        plt.ylabel("Cumulative Distribution Function (CDF)")

        #plt.axis([0, max(both_x), 0.9, 1])
        plt.axis([0, 20, 0.9, 1])

        #plt.plot(both_x, both_y, label='All', marker='^', color='0.6', linestyle='-', markevery=len(both_x)/5000000)
        #plt.plot(rust_x, rust_y, label='Rust', marker='o', color='0.35', linestyle='-', markevery=len(rust_x)/200000)
        #plt.plot(c_x, c_y, label='C/C++', marker='s', color='0', linestyle='-', markevery=len(c_x)/5000000)

        plt.plot(both_x, both_y, label='All', marker='^', color='0', linestyle='-', markevery=len(both_x)/5000000)
        plt.plot(rust_x, rust_y, label='Rust', marker='o', color='red', linestyle='-', markevery=len(rust_x)/200000)
        plt.plot(c_x, c_y, label='C/C++', marker='s', color='blue', linestyle='-', markevery=len(c_x)/5000000)

        # Generate and save graph
        #plt.grid(True)
        plt.grid(True, color='0.45')
        plt.plot()
        plt.legend(loc='upper center',bbox_to_anchor=(0.5, -0.15),shadow=True, ncol=3)
        print("Saving tps...")
        cdf_plt.savefig("output/graphs/tps.pdf", bbox_inches='tight')

        ### Make a CDF for number of visitor points
        #print("rust_vps")
        #print(rust_vps)
        #print("c_vps")
        #print(c_vps)
        #print("both_vps")
        #print(both_vps)
        rust_x = np.sort(np.array(rust_vps))
        rust_y = np.arange(1, len(rust_x)+1)/len(rust_x)

        c_x = np.sort(np.array(c_vps))
        c_y = np.arange(1, len(c_x)+1)/len(c_x)

        both_x = np.sort(np.array(both_vps))
        both_y = np.arange(1, len(both_x)+1)/len(both_x)

        print("Generating CDF for number of visitor points...")
        cdf_plt = plt.figure()

        # Graph labels
        plt.title("Number of Visitor Points")
        plt.xlabel("Number of Visitor Points")
        plt.ylabel("Cumulative Distribution Function (CDF)")

        #plt.axis([0, max(both_x), 0.9, 1])
        plt.axis([0, 10, 0.9, 1])

        #plt.plot(both_x, both_y, label='All', marker='^', color='0.6', linestyle='-', markevery=len(both_x)/500000)
        #plt.plot(rust_x, rust_y, label='Rust', marker='o', color='0.35', linestyle='-', markevery=len(rust_x)/200000)
        #plt.plot(c_x, c_y, label='C/C++', marker='s', color='0', linestyle='-', markevery=len(c_x)/500000)

        plt.plot(both_x, both_y, label='All', marker='^', color='0', linestyle='-', markevery=len(both_x)/250000)
        plt.plot(rust_x, rust_y, label='Rust', marker='o', color='red', linestyle='-', markevery=len(rust_x)/200000)
        plt.plot(c_x, c_y, label='C/C++', marker='s', color='blue', linestyle='-', markevery=len(c_x)/250000)

        # Generate and save graph
        #plt.grid(True)
        plt.grid(True, color='0.45')
        plt.plot()
        plt.legend(loc='upper center',bbox_to_anchor=(0.5, -0.15),shadow=True, ncol=3)
        print("Saving vps...")
        cdf_plt.savefig("output/graphs/vps.pdf", bbox_inches='tight')

        ### Make a CDF for number of invocations 
        #print("rust_invos")
        #print(rust_invos)

        rust_x = np.sort(np.array(rust_invos))
        rust_y = np.arange(1, len(rust_x)+1)/len(rust_x)

        #print("c_invos")
        #print(c_invos)

        c_x = np.sort(np.array(c_invos))
        c_y = np.arange(1, len(c_x)+1)/len(c_x)

        #print("both_invos")
        #print(both_invos)

        both_x = np.sort(np.array(both_invos))
        both_y = np.arange(1, len(both_x)+1)/len(both_x)

        print("Generating CDF for number of invocations...")
        cdf_plt = plt.figure()

        # Graph labels
        plt.title("Number of Invocations")
        plt.xlabel("Number of Invocations")
        plt.ylabel("Cumulative Distribution Function (CDF)")

        #plt.axis([0, max(both_x), 0.9, 1])
        plt.axis([0, 30, 0.8, 1])

        #plt.plot(both_x, both_y, label='All', marker='^', color='0.6', linestyle='-', markevery=len(both_x)/1000000)
        #plt.plot(rust_x, rust_y, label='Rust', marker='o', color='0.35', linestyle='-', markevery=len(rust_x)/200000)
        #plt.plot(c_x, c_y, label='C/C++', marker='s', color='0', linestyle='-', markevery=len(c_x)/1000000)

        plt.plot(both_x, both_y, label='All', marker='^', color='0', linestyle='-', markevery=len(both_x)/750000)
        plt.plot(rust_x, rust_y, label='Rust', marker='o', color='red', linestyle='-', markevery=len(rust_x)/200000)
        plt.plot(c_x, c_y, label='C/C++', marker='s', color='blue', linestyle='-', markevery=len(c_x)/750000)

        # Generate and save graph
        #plt.grid(True)
        plt.grid(True, color='0.45')
        plt.plot()
        plt.legend(loc='upper center',bbox_to_anchor=(0.5, -0.15),shadow=True, ncol=3)
        print("Saving invos...")
        cdf_plt.savefig("output/graphs/invos.pdf", bbox_inches='tight')

if __name__ == "__main__":

    # Version that takes a file of binaries
    parser = ArgumentParser()
    parser.add_argument("bin_paths", type=str, help="""
    Path of file that contains list of binaries to generate metrics for 
    """)
    args = parser.parse_args()

    # Find each relevant binary
    # TODO: call find_elf.sh from python

    # For each elf, create a json file of function metadata 
    elf_reader(args.bin_paths)

    # Combine each elf json file into a single json file of function metadata 
    combine_elf_results(args.bin_paths)

    # For each objdump, create a json file of function metadata 
    obj_reader(args.bin_paths)

    # Combine each obj json file into a single json file of function metadata 
    combine_obj_results(args.bin_paths)

    # Combine elf and obj json metadata into one json file of function metadata
    combine_elf_and_obj_results()

    # Use call sites in function metadata to find transfer and visitor points and save 
    get_transfer_points()

    # Use call sites in function metadata to find invocations  
    get_invocation_points()

    # Make graphs from metadata
    generate_cdfs()
