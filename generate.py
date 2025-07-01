#!/usr/bin/env python3

import datetime
import datetime
import logging
import optparse
import os
import pathlib
import plistlib
import sys
import yaml

CONFIG_PATH = "config.yaml"
MD_PATH = "munki-mscp-generation-summary.md"
OUTPUT_PATH = "munki"

SHEBANG_BASH = "#!/bin/bash\n"
SHEBANG_ZSH = "#!/bin/zsh\n"

DEFAULT_CONFIG = {
	"fields_from_rule": {
		"display_name": "title",
		"description": "discussion"
	},
	"static_fields": {
		"category": "Compliance",
		"installer_type": "nopkg",
		"unattended_install": True
	},
	"metadata": {
		"created_by": "munki-mscp-generator",
		"creation_date": "today"
	}
}

# ----------------------------------------
#            Path Navigation
# ----------------------------------------
def get_all_input_paths(baseline_path, baseline_name, custom_path, rules_path, folder_path):
	check_folder_path(baseline_path, custom_path, rules_path, folder_path)
	baseline_path = get_baseline_path(baseline_path, baseline_name, folder_path)
	custom_path = get_custom_path(custom_path, folder_path)
	rules_path = get_rules_path(rules_path, folder_path)
	return baseline_path, custom_path, rules_path

def check_folder_path(baseline_path, custom_path, rules_path, folder_path):
	if not (baseline_path and custom_path and rules_path) and folder_path:
		# folder needed and given
		if not os.path.exists(folder_path):
			# folder does not exists
			logging.error(f"Given directory {folder_path} does not exist.")
			sys.exit(1)
		elif not os.access(folder_path, os.R_OK):
			# folder exists but no access
			logging.error(f"No access to {folder_path}")
			sys.exit(1)	

def get_rules_path(rules_path, folder_path):
	original_rules_path = rules_path
	# if no rules path given check if we can make it
	if not rules_path:
		if folder_path:
			rules_path = os.path.join(folder_path, "rules")
		else:
			rules_path = "rules"
		if not os.path.exists(rules_path):
			# no rules subdirectory found
			logging.error(f"No rules directory found, thus no items can be created from rules.")
			sys.exit(1)	
	# if rules folder contains only one folder, go one level deeper
	rules_path = nav_down(rules_path)
	# if new folder contains a rules folder, nav to it
	paths = os.listdir(rules_path)
	if "rules" in paths:
		rules_path = os.path.join(rules_path, "rules")
	if original_rules_path != rules_path:
		logging.info(f"Using directory {rules_path} as rules directory.")
	return rules_path	

def nav_down(path):
	if path:
		is_path_new = True
		while(is_path_new):
			is_path_new = False
			if os.path.exists(path):
				paths = [new_path for new_path in os.listdir(path) if not new_path.startswith(".")]
				if len(paths) == 1 and os.path.isdir(os.path.join(path, paths[0])):
					path = os.path.join(path, paths[0])
					is_path_new = True
	return path

def get_custom_path(custom_path, folder_path):
	original_path = custom_path
	# if no baseline path given check if we can make it
	if not custom_path:
		if folder_path:
			custom_path = os.path.join(folder_path, "custom")
		else:
			custom_path = "custom"
		if not os.path.exists(custom_path):
			# no custom subdirectory found
			logging.warning(f"No custom directory found. Continuing without.")
			return None
	# if folder has rules subdirectory go there
	if os.path.exists(os.path.join(custom_path, "rules")):
		custom_path = os.path.join(custom_path, "rules")
	if original_path != custom_path:
		logging.info(f"Using directory {custom_path} as custom directory.")
	return custom_path

def get_baseline_path(baseline_path, baseline_name, folder_path):
	original_path = baseline_path
	# if no baseline path given check if we can make it
	# can be in given folder, baseline folder, or current directory
	if not baseline_path:
		if folder_path:
			baseline_path = os.path.join(folder_path, "baselines")
		elif os.path.exists("baselines"):
			baseline_path = "baselines"
		elif not baseline_name:
			logging.warning(f"No custom baseline file provided. Munki items will be generated for all rules provided.")
			baseline_path = None
		if baseline_path and (not os.path.exists(baseline_path)):
			# no baselines subdirectory found
			if baseline_name:
				# specific name given: error file not found
				logging.error(f"Expected custom baseline named {baseline_name} in {baseline_path} but no such directory {baseline_path} was found.")
				sys.exit(1)
			else:
				# no specific path or name given, fall to default
				if folder_path:
					logging.warning(f"No path to a custom baseline was given. The directory {folder_path} was specified, but does not contain a 'baselines' subdirectory. Thus no custom baseline file could be found. Munki items will be generated for all rules provided.")
				else:
					logging.warning(f"No custom baseline file provided. Munki items will be generated for all rules provided.")
				baseline_path = None
		else:
			# baselines subdirectory found
			# if name is given
			if baseline_name:
				if not baseline_path:
					baseline_path = ""
				if not (baseline_name.endswith(".yaml" or baseline_name.endswith(".yml"))):
					baseline_name_1 = baseline_name + ".yaml"
					baseline_path_1 = os.path.join(baseline_path, baseline_name_1)
					baseline_name_2 = baseline_name + ".yml"
					baseline_path_2 = os.path.join(baseline_path, baseline_name_2)
					if os.path.exists(baseline_path_1):
						baseline_path = baseline_path_1
					elif os.path.exists(baseline_path_2):
						baseline_path = baseline_path_2
					else:
						if baseline_path == "":
							baseline_path = "current directory"
						logging.error(f"Expected custom baseline yaml file named {baseline_name} in {baseline_path} but no such file was found.")
						sys.exit(1)
				else:
					baseline_path = os.path.join(baseline_path, baseline_name)
			else:
				if not baseline_path:
					logging.warning(f"No path to a custom baseline file found in {baseline_path} so munki items will be generated for all rules provided.")
					baseline_path = None
				# have directory, if it contains only one file use that file
				else:
					file_names = [file_name for file_name in os.listdir(baseline_path) if (file_name.endswith(".yaml") or file_name.endswith(".yml"))]
					if len(file_names) == 1:
						baseline_path = os.path.join(baseline_path, file_names[0])
					elif len(file_names) == 0:
						logging.warning(f"No path to a custom baseline file found in {baseline_path} so munki items will be generated for all rules provided.")
						baseline_path = None
					else:
						logging.error(f"Multiple files found in {baseline_path}. Please specify the name of your custom baseline.")
						sys.exit(1)
	elif not os.path.exists(baseline_path):
		logging.error(f"Custom baseline file {baseline_path} is not present.")
		sys.exit(1)
	if original_path != baseline_path:
		logging.info(f"Using directory {baseline_path} as baseline path.")
	return baseline_path

# ----------------------------------------
#            Baseline
# ----------------------------------------
def get_baseline_profile(baseline, baseline_path) -> list:
	if baseline and "profile" in baseline:
		profile = baseline["profile"]
		if type(profile) == list and len(profile) > 0:
			return profile
		else:
			logging.warning(f"Provided baseline file {baseline_path} contains no rules, so there are no items to generate.")
			sys.exit(0)
	else:
		logging.error(f"Provided baseline file {baseline_path} contains no profile.")
		sys.exit(1)

def check_baseline_defaults(baseline, config):
	if ("odv_default" not in config) and ("parent_values" in baseline):
		config["odv_default"] = baseline["parent_values"]

# ----------------------------------------
#              Rules
# ----------------------------------------
def find_rule(rule_name, rules_folder, looking_for_custom=False):
	rules_path = pathlib.Path(rules_folder)
	files = []
	# add extension if missing
	# find location of rule
	if not (rule_name.endswith(".yaml") or rule_name.endswith(".yml")):
			files += list(rules_path.rglob(rule_name + ".yaml"))
			files += list(rules_path.rglob(rule_name + ".yml"))
	else:
		files += list(rules_path.rglob(rule_name))
	# check that rule exists in exactly one location
	if len(files) < 1:
		if looking_for_custom:
			return None
		else:	
			logging.error(f"Rule {rule_name} was not found in {rules_path}.")
			sys.exit(1)
	elif len(files) > 1:
		s = "rule"
		if looking_for_custom:
			s = "custom for rule"
		logging.error(f"More than one {s} {rule_name} found. Please make sure only one file exists per rule.")
		logging.error(f"Files found: {files}.")
		sys.exit(1)
	else:
		rules_path = files[0]
	# read rule
	return read_yaml(rules_path)

def process_rule(rule_name, rules_folder, output_path, config, odv_level_items, custom_path, separate_fix, include_echo, config_profile_list_file, script_summary):
	rule = find_rule(rule_name, rules_folder)
	rule_name = get_rule_name(rule_name, rule)
	custom = get_custom(rule, rule_name, custom_path, odv_level_items, config)
	if rule_has_fix(rule, rule_name, config_profile_list_file, custom, script_summary):
		create_munki_item(rule, rule_name, output_path, config, odv_level_items, custom_path, separate_fix, include_echo, config_profile_list_file, custom)

def get_all_rules(rules_folder):
	rules_path = pathlib.Path(rules_folder)
	result = list(rules_path.rglob("*.yaml"))
	result += list(rules_path.rglob("*.yml"))
	return result

def process_all_rules(rules_folder, output_path, config, odv_level_items, custom_path, separate_fix, include_echo, config_profile_list_file, script_summary):
	rule_paths = get_all_rules(rules_folder)
	for rule_path in rule_paths:
		rule = read_yaml(rule_path)
		rule_name = get_rule_name(rule_path, rule)
		custom = get_custom(rule, rule_name, custom_path, odv_level_items, config)
		if rule_has_fix(rule, rule_name, config_profile_list_file, custom, script_summary):	
			create_munki_item(rule, rule_name, output_path, config, odv_level_items, custom_path, separate_fix, include_echo, config_profile_list_file, custom)

def rule_has_fix(rule, name, config_profile_list_file, custom, script_summary):
	if "check" in rule and "result" in rule and "fix" in rule:
		# there is fix -> check if fix can be in munki item
		# check if fix in configuration profile
		if config_profile_list_file:
			if is_fix_by_config_profile(rule["fix"]):
				if "mobileconfig_info" in rule:
					# if mobileconfig_info given add this as info, otherwise info = mobileconfig
					if rule["mobileconfig_info"]:
						script_summary["config_items_made"].append((name, rule["mobileconfig_info"], custom))
					else:
						script_summary["config_items_made"].append((name, rule["mobileconfig"], custom))
				else:
					logging.error(f"Rule {name} has a fix implemented by a Configuration Profile, but is missing the mobileconfig_info key.")
					sys.exit(1)
				return True
		# check if fix is bash script
		fix = rule["fix"].rstrip("\n")
		lines = fix.splitlines()
		if "source" in lines[0]:
			chunks = rule["fix"].split("----")
			if len(chunks) > 2:
				note = "----".join(chunks[2:]).lstrip(" \n").rstrip(" \n")
				script_summary["items_made"].append((name, note, custom))
			else:
				script_summary["items_made"].append((name, None, None))
			return True
		else:
			# Fix must be impolemented outside of a munki item. Item is skipped.
			script_summary["items_skipped"].append((name, fix, custom))
			return False
	else:
		script_summary["rules_no_fix"].append(name)
		False

def is_fix_by_config_profile(fix):
	return fix.rstrip("\n").lstrip("\n") == "This is implemented by a Configuration Profile."

def get_rule_name(rule_path, rule):
	if "id" in rule:
		return rule["id"]
	else:
		#get name from file name
		return pathlib.Path(filename).stem

# ----------------------------------------
#              Munki Items
# ----------------------------------------

def create_munki_item(rule, name, output_path, config, odv_level_items, custom_path, separate_fix, include_echo, config_profile_list_file, custom):
	item = dict()
	# name
	munki_item_name = get_munki_item_name(name, config)
	item["name"] = munki_item_name
	munki_item_name_file_name = munki_item_name
	# metadata
	if "metadata" in config:
		metadata = config["metadata"]
		for key in metadata:
			if metadata[key] == "today":
				metadata[key] = datetime.datetime.now()
		item["_metadata"] = metadata
	# version
	if "version" in config:
		munki_item_name_file_name += f"{config['delimiter']}{config['version']}"
		item["version"] = str(config["version"])
	# non static keys
	if "fields_from_rule" in config:
		for key in config["fields_from_rule"]:
			add_rule_info_to_item(item, rule, key, config["fields_from_rule"][key], custom)
	# static keys
	if "static_fields" in config:
		for key in config["static_fields"]:
			item[key] = config["static_fields"][key]
	# check / fix
	# fix is with configuration profile
	if is_fix_by_config_profile(rule["fix"]):
		if config_profile_list_file:
			add_config_profile_for_install(item, name, config_profile_list_file, separate_fix, include_echo)
			add_config_profile_for_uninstall(item, name, config_profile_list_file, include_echo)
		else:
			logging.error("Trying to crate munki items for rules where fix must be implemented by a Configuration Profile but no config_profile_list_file is given. Something went wrong!")
			sys.exit(1)
	# fix is code
	else:
		if "discussion" in rule:
			prefix_code = get_code_from_discussion(rule["discussion"])
		else:
			prefix_code = ""
		if separate_fix:
			add_check_to_installcheck(item, rule, name, custom, prefix_code, include_echo)
			add_fix_to_preinstall(item, rule, name, custom, prefix_code, include_echo)
		else:
			add_check_and_fix_to_installcheck(item, rule, name, custom, prefix_code, include_echo)
	# write
	write_munki_item(munki_item_name_file_name + ".plist", output_path, item)

def get_custom(rule, name, custom_path, odv_level_items, config):
	custom = None
	if "odv" in rule:
		# check if custom
		if custom_path:
			custom = find_rule(name, custom_path, looking_for_custom=True)
		else:
			custom = None
		if custom:
			if "odv" in custom and "custom" in custom["odv"]:
				custom = str(custom["odv"]["custom"])
			else:
				logging.error(f"Custom for {name} does not contain expected odv and custom keys.")
				sys.exit(1)
		else:
			# check if level
			if name in odv_level_items:
				level = odv_level_items[name]
			elif "odv_default" in config:
				# use default  
				level = config["odv_default"]
			else:
				logging.error(f"Rule {name} requires a custom odv, but none was provided and a default was not given in the config file.")
				sys.exit(1)
			if level in rule["odv"]:
				custom = str(rule["odv"][level])
			else:
				logging.error(f"Should use {level} for odv for rule {name}, however no such odv value is given in this rule.")
				sys.exit(1)
	return custom

def add_rule_info_to_item(item, rule, item_field, rule_field, custom):
	if rule_field in rule:
		value = rule[rule_field]
		if custom and type(value) == str:
			value = value.replace("$ODV", custom)
		item[item_field] = value

def create_if_else_script(shebang, prefix, comp, if_script, else_script, ends_with_exit1 = True):
	s = shebang 
	if prefix and prefix != "":
		s += prefix.lstrip("\n") + "\n"
	s += f"if {comp}; then\n"
	s += "".join([f"\t{line}\n" for line in if_script.splitlines()])
	if else_script and else_script != "":
			s += f'else\n'
			s += "".join([f"\t{line}\n" for line in else_script.splitlines()])
	s += "fi"
	if ends_with_exit1:
		s += "\n\nexit 1"
	return s

def add_check_and_fix_to_installcheck(item, rule, rule_name, custom, prefix_code, include_echo):
	# store check variable
	prefix_code += "\n\n" + create_bash_var_str(rule['check'])
	# compare to expected result
	comparison = create_bash_compare_str(rule["result"], rule_name)
	# fix
	fix = create_bash_fix_str(rule["fix"], rule_name, item, include_echo)
	# suffix
	else_script = None
	if include_echo:
		else_script = 'echo "No fix needed"'
	# write script
	s = create_if_else_script(SHEBANG_BASH, prefix_code, comparison, fix, else_script)
	if custom:
		s = s.replace("$ODV", custom)
	item["installcheck_script"] = s

def add_check_to_installcheck(item, rule, rule_name, custom, prefix_code, include_echo):
	# store check variable
	prefix_code += "\n\n" + create_bash_var_str(rule['check'])
	# compare to expected result
	comparison = create_bash_compare_str(rule["result"], rule_name)
	# fix
	if_script = "exit 0"
	# suffix
	else_script = None
	if include_echo:
		else_script = 'echo "No fix needed"'
	# write script
	s = create_if_else_script(SHEBANG_BASH, prefix_code, comparison, if_script, else_script)
	if custom:
		s = s.replace("$ODV", custom)
	item["installcheck_script"] = s

def add_fix_to_preinstall(item, rule, rule_name, custom, prefix_code, include_echo):
	# prefix
	s = SHEBANG_BASH 
	# add prefix code
	s += prefix_code + "\n"
	# fix
	s += create_bash_fix_str(rule["fix"], rule_name, item, include_echo)
	if custom:
		s = s.replace("$ODV", custom)
	item["preinstall_script"] = s

def create_bash_var_str(check):
	check = check.lstrip("\n")
	check = check.rstrip("\n")
	return f"result_value=$({check})\n"

def create_bash_compare_str(result_dict, rule_name):
	keys = list(result_dict.keys())
	if len(keys) != 1:
		logging.error(f"Result for rule {rule_name} not formatted as expected, so cannot be processed by this script.")
		sys.exit(1)
	key = keys[0]
	return f'[[ $result_value != "{result_dict[key]}" ]]'

def create_bash_fix_str(fix, rule_name, item, include_echo):
	result = "" 
	if include_echo:
		result += 'echo "Applying fix"\n'
	fix = fix.rstrip(" \n")
	chunks = fix.split("----")
	# check source
	if chunks[0].lstrip(" \n").rstrip(" \n") == "[source,bash]":
		fix = chunks[1]
		if fix.startswith("\n"):
			fix = fix[1:]
		# add code to string
		for line in fix.splitlines():
			result += f"{line}\n"
	else:
		logging.error(f"Fix for rule {rule_name} not formatted as expected, so cannot be processed by this script.")
		logging.error("Fix:")
		logging.error(fix)
		sys.exit(1)
	# check if there are notes
	if len(chunks) > 2:
		note = "----".join(chunks[2:]).lstrip(" \n").rstrip(" \n")
		if note.startswith("NOTE"):
			note = note[len("NOTE"):]
		note = note.lstrip(" :-")
		# add note to item
		if "notes" in item:
			item["notes"] = item["notes"] + "\n\n" + note
		elif note and note != "":
			item["notes"] = note
		# warn
		# logging.info(f"Note for item {rule_name}\n\t{note}")
	return result

def add_config_profile_for_install(item, name, file, separate_fix, echo):
	prefix = f'PLIST_PATH="{file}"\n\n'
	prefix2 = f"/usr/libexec/PlistBuddy -c 'Print :RequestedRules' $PLIST_PATH | /usr/bin/grep -qE '^\\s+{name}$'\n"
	comp = "[[ ! $? ]]"
	fix = ""
	else_script = None
	if echo:
			fix += 'echo "Adding to plist file"\n'
			else_script = 'echo "Already in plist file"\n'
	fix += "/usr/libexec/PlistBuddy -c 'Add :RequestedRules array' $PLIST_PATH\n"
	fix += f"/usr/libexec/PlistBuddy -c 'Add :RequestedRules: string {name}' $PLIST_PATH\n"
	if separate_fix:
		item["installcheck_script"] = create_if_else_script(SHEBANG_ZSH, prefix + prefix2, comp, "exit 0", else_script)
		item["preinstall_script"] = SHEBANG_ZSH + prefix + fix
	else:
		item["installcheck_script"] = create_if_else_script(SHEBANG_ZSH, prefix + prefix2, comp, fix, else_script)

def add_config_profile_for_uninstall(item, name, file, echo):
	if "autoremove" not in item:
		item["autoremove"] = True
	if "unattended_uninstall" not in item:
		item["unattended_uninstall"] = True
	if "uninstall_method" not in item:
		item["uninstall_method"] = "uninstall_script"

	# uninstall
	prefix = f'PLIST_PATH="{file}"\n\n'
	# get number of times item in rules
	prefix2 = f'requested_rule=$(/usr/libexec/PlistBuddy -c "Print :RequestedRules" $PLIST_PATH | /usr/bin/grep -n -E "^\\s+{name}$" | /usr/bin/awk -F ":" \'{"{print $1}"}\')\n'
	# if 1 then remove it
	comp = '[ ! -z "$requested_rule" ]'
	# remove it
	remove = '# Item to delete is the number minus two\nitemToDelete=$(($requested_rule-2))\n/usr/libexec/PlistBuddy -c "Delete :RequestedRules:$itemToDelete" $PLIST_PATH\n'
	if echo:
		remove += 'echo "Removed from plist file"\n'
	# else do nothing
	else_script = None
	if echo:
		else_script = 'echo "Item already removed from plist file - nothing to do"\n'
	item["uninstall_script"] = create_if_else_script(SHEBANG_ZSH, prefix + prefix2, comp, remove, else_script, False)

	# uninstall check
	prefix3 = f'/usr/libexec/PlistBuddy -c \'Print :RequestedRules\' $PLIST_PATH | grep -qE "^\\s+{name}$"\n'
	item["uninstall_check"] = create_if_else_script(SHEBANG_ZSH, prefix + prefix3,  "[[ $? ]]", "exit 0", None)

def write_munki_item(name, output_path, item):
	item_path = os.path.join(output_path, name)
	# open file
	with open(item_path, "wb+") as fp:
		try:
			# make sure we are at start of file
			fp.seek(0)
			# write to file
			plistlib.dump(item, fp, fmt=plistlib.FMT_XML, sort_keys=False)
			# remove any excess of old file
			fp.truncate()
		except Exception as e:
			logging.error(f"Could not write to file {item_path} in munki directory.")
			logging.error(e, exc_info=True)
			sys.exit(1)

def get_munki_item_name(name, config):
	name = name.replace('_', config["delimiter"])
	if "prefix" in config:
		name = config["prefix"] + name
	if "suffix" in config:
		name += config["suffix"]
	return name

def prep_munki_item_dir(folder_path):
	if not os.path.exists(folder_path):
		# make dir
		logging.info(f"Output path {folder_path} does not exist, so will be created.")
		os.makedirs(folder_path)

def get_code_from_discussion(discussion):
	result = ""
	chunks = discussion.split("----")
	if len(chunks) > 1:
		for i, s in enumerate(chunks):
			if s.endswith("[source,bash]\n") and i < len(chunks)-1:
				result += chunks[i+1].lstrip(" \n").rstrip(" \n")
				result += "\n"
	return result

# ----------------------------------------
#                Config 
# ----------------------------------------
def get_config(config_path, prefix, suffix, version):
	if config_path:
		# file specified 
		if not os.path.exists(config_path):
			# file specified but not there -> error: user provided file should exist
			logging.error(f"Configuration file {config_path} is not present.")
			sys.exit(1)
		else:
			result = read_yaml(config_path)
	elif not os.path.exists(CONFIG_PATH):
		# file was not user provided and was not there -> warning: use defauls
		logging.warning("No configuration file is present. Will continue with default settings.")
		result = DEFAULT_CONFIG
	else:
		logging.info(f"Using configuration file found at {CONFIG_PATH}.")
		result = read_yaml(CONFIG_PATH)
	if not result:
		result = dict()
	check_config(result)
	format_prefix_suffix(result, prefix, suffix, version)
	add_default_config_values(result)
	return result

def check_config(config):
	if type(config) == dict:
		keys = config.keys()
		if set(keys).issubset({"fields_from_rule", "static_fields", "metadata", "odv_default", "odv_level", "prefix", "suffix", "version", "delimiter", "config_profile_list_file"}):
			for key in keys:
				if key in ["odv_default", "prefix", "suffix", "delimiter", "config_profile_list_file"]:
					if type(config[key]) != str:
						logging.error(f"Unexpected format of config file. {key} is expected to be type string but is type {type(config[key])}. Please update config file.")
						sys.exit(1)
				elif key == "version":
					if type(config[key]) != str and type(config[key]) != int and type(config[key]) != float:
						logging.error(f"Unexpected format of config file. {key} is expected to be type string, int or float, but is type {type(config[key])}. Please update config file.")
						sys.exit(1)
				elif not type(config[key]) == dict:
					logging.error(f"Unexpected format of config file. {key} is expected to be type dictionary but is type {type(config[key])}. Please update config file.")
					sys.exit(1)
				if key == "odv_level":
					for key in config["odv_level"]:
						if type(config["odv_level"][key]) != list:
							logging.error(f"Unexpected format of config file. {key} is expected to be type list but is type {type(config['odv_level'][key])}. Please update config file.")
							sys.exit(1)
		else:
			logging.error(f'Unknown key(s) in config file: {str(set(keys).difference({"fields_from_rule", "static_fields", "metadata", "odv_default", "odv_level", "prefix", "suffix"}))[1 : -1]}. Please update config file.')
			sys.exit(1)
	else:
		logging.error(f"Unexpected format of config file. Expected file in the format of dictionary, but indtead file is formatted as {type(config)}. Please update config file.")
		sys.exit(1)
	return True

def get_all_items_odv_level(config):
	result = dict()
	if "odv_level" in config:
		for key in config["odv_level"]:
			for rule in config["odv_level"][key]:
				result[rule] = key
	return result

def format_prefix_suffix(config, prefix, suffix, version):
	if prefix:
		if "prefix" in config:
			config["prefix"] = prefix + config["prefix"]
		else:
			config["prefix"] = prefix
	if suffix:
		if "suffix" in config:
			config["suffix"] = config["suffix"] + suffix 
		else:
			config["suffix"] = suffix
	if version:
		config["version"] = version

def add_default_config_values(config):
	if "delimiter" not in config:
		config["delimiter"] = "-"
	if "static_fields" not in config:
		config["static_fields"] = {"installer_type" : "nopkg", "unattended_install": True}
		logging.warning("installer_type not specified for munki items. Default (nopkg) will be used.")
		logging.warning("unattended_install not specified for munki items. Default (True) will be used.")
	elif "installer_type" not in config["static_fields"]:
		config["static_fields"]["installer_type"] = "nopkg"
		logging.warning("No installer_type specified for munki items. Default (nopkg) will be used.")
	elif "unattended_install" not in config["static_fields"]:
		config["static_fields"]["unattended_install"] = True
		logging.warning("unattended_install not specified for munki items. Default (True) will be used.")

def update_config_profile_list_file_from_config(config_profile_list_file, config):
	if config_profile_list_file:
		return config_profile_list_file
	if "config_profile_list_file" not in config:
		return config_profile_list_file
	return config["config_profile_list_file" ]

# ----------------------------------------
#                Markdown
# ----------------------------------------
def write_md_file(md_file, system_settings):
	md = md_description(system_settings)
	try:
		f = open(md_file, "w")
		f.write(md)
		f.close()
		logging.info("Markdown file successfully updated.")
	except Exception as e:
		logging.error(f"Unable to write to {md_file}")
		logging.error(e, exc_info=True)
		sys.exit(1)

def md_description(system_settings):
	s = "# Summary of munki items generated by munki-mscp-generator\n\n"

	s += '## Generated Items\n\n'

	if len(system_settings["items_made"]) > 0:
		s += "### Generated munki items for the following rules where fixes are implemented with a script:\n"
		for name, note, custom in system_settings["items_made"]:
			s += f"* {name}\n"
			if note:
				if custom:
					note = note.replace("$ODV", custom)
				note = note.replace("*", "\\*")
				s += "\n".join([f"    * {line}" for line in note.splitlines()])
				s += "\n"
		s += "\n\n"

	if len(system_settings["config_items_made"]) > 0:
		s += "### Generated munki items for the following rules where fixes must be implemented by a Configuration Profile:\n"
		for name, info, custom in system_settings["config_items_made"]:
			s += f"* {name}\n"
			if type(info) == dict:
				for key in info:
					keys = key
					if not custom:
						custom = "$ODV"
					s += f"    * In preference domain {keys}:\n".replace("$ODV", custom)
					d = info[key]
					if d:
						for key in d:
							s += f"        * `{key}` must be set to `{d[key]}`\n".replace("$ODV", custom)
			else:
				s += f"    * `mobileconfig` = {info}, no `mobileconfig_info` given\n"

	if len(system_settings["items_made"]) + len(system_settings["items_skipped"]) < 1:
		s += "No munki items generated.\n\n"

	s += '## Skipped Items\n\n'
	if len(system_settings["items_skipped"]) > 0:
		s += "### The following rules have fixes that must be addressed outside of a munki item:\n"
		for name, fix, custom in system_settings["items_skipped"]:
			s += f"* {name} with the fix:\n"
			if custom:
				fix = fix.replace("$ODV", custom)
			fix = fix.replace("*", "\*")
			s += "".join([f"    * {line}\n" if line not in ["", " "] else "" for line in fix.splitlines()])
		s += "\n\n"

	if len(system_settings["rules_no_fix"]) > 0:
		s += "### The following rules had no defined fix, so were skipped:\n* "
		s += "\n* ".join(system_settings["rules_no_fix"])
		s += "\n\n"

	s = s.replace("&", "\&")
	s = s.replace("[", "\[")
	s = s.replace("<", "\<")
	s = s.replace("]\n    * `\n    *", "\\<")
	s = s.replace("----", "\----")
	return s


# ----------------------------------------
#           Helper functions
# ----------------------------------------

def read_yaml(file_path) -> dict:
	if not os.access(file_path, os.R_OK):
		logging.error(f"No access to {file_path}")
		sys.exit(1)	
	with open(file_path, "r") as file_yaml:
		try:
			result = yaml.safe_load(file_yaml)
			return result
		except yaml.YAMLError as e:
			logging.error(f"Unable to load {file_path}")
			logging.error(e, exc_info=True)
			sys.exit(1)

def setup_logging():
	logging.basicConfig(
		level=logging.DEBUG,
		format="%(asctime)s - %(levelname)s (%(module)s): %(message)s",
		datefmt='%d/%m/%Y %H:%M:%S',
		stream=sys.stdout)

# ----------------------------------------
#                 Main
# ----------------------------------------

def process_options():
	parser = optparse.OptionParser()
	parser.set_usage('Usage: %prog [options]')
	parser.add_option('--baseline-path', '-b', dest='baseline_path',
						help='Optional path to custom baseline yaml file.')
	parser.add_option('--baseline-name', '-n', dest='baseline_name',
						help='Optional name of baseline yaml file.')
	parser.add_option('--custom', '-c', dest='custom',
						help='Optional path to custom folder.')
	parser.add_option('--rules', '-r', dest='rules',
						help='Optional path to rules folder.')
	parser.add_option('--folder', '-f', dest='folder',
						help='Optional path to a folder optionally containing a baselines, custom and rules folder. These folders will be used if paths are not directly specified.')
	parser.add_option('--config', '-y', dest='config_file',
						help=f'Optional path to the configuration yaml file, which specifies values for the munki item. Defaults to {CONFIG_PATH}')
	parser.add_option('--munki', '-m', dest='output_path', default=OUTPUT_PATH,
						help=f'Optional path to the directory generated munki files should be written to. Defaults to {OUTPUT_PATH}')
	parser.add_option('--prefix', dest='prefix',
						help=f'Optional prefix to add to the name of every generated munki item and it\'s file name.')
	parser.add_option('--suffix', dest='suffix',
						help=f'Optional suffix to add to the name of every generated munki item and it\'s file name..')
	parser.add_option('--version', '-v', dest='version',
						help=f'Optional version to be set in every munki item and appended to the name of every generated munki item. Specifying a version here will override a version given in the configuration yaml file.')
	parser.add_option('--separate', '-s', dest='separate_fix', action='store_true',
						help='Write fix script in preinstall_script, rather than in installcheck_script.')
	parser.add_option('--no-munki-output', dest='no_echo', action='store_true',
						help='Write fix script in preinstall_script, rather than in installcheck_script.')
	parser.add_option('--config-profile-list-file', dest='config_profile_list_file',
						help='Optional path to the file where munki items will write to if their fix can only be implemented by a configuration profile. Specifying a file path here will override a file given in the configuration yaml file.')
	parser.add_option('--markdown', dest='markdown_path', default=MD_PATH,
						help=f'Optional file name to print markdown summary of how the rules were processed by this script. Defaults to {MD_PATH}')
	options, _ = parser.parse_args()
	return options.baseline_path, options.baseline_name, options.custom, options.rules, options.folder, options.config_file, options.output_path, options.prefix, options.suffix, options.version, options.separate_fix, not options.no_echo, options.config_profile_list_file, options.markdown_path


def main():
	setup_logging()
	baseline_path, baseline_name, custom_path, rules_path, folder_path, config_path, output_path, prefix, suffix, version, separate_fix, include_echo, config_profile_list_file, md_path = process_options()
	baseline_path, custom_path, rules_path = get_all_input_paths(baseline_path, baseline_name, custom_path, rules_path, folder_path)

	script_summary = {"items_made":[], "config_items_made":[], "items_skipped":[], "rules_no_fix":[]}

	config = get_config(config_path, prefix, suffix, version)
	odv_level_items = get_all_items_odv_level(config)
	config_profile_list_file = update_config_profile_list_file_from_config(config_profile_list_file, config)

	prep_munki_item_dir(output_path)

	if baseline_path:
		baseline = read_yaml(baseline_path)
		check_baseline_defaults(baseline, config)
		profile = get_baseline_profile(baseline, baseline_path)
		for section in profile:
			if "rules" not in section or type(section["rules"]) != list:
				logging.error(f"Unexpected configuration of baseline file {baseline_path} rules not found where expected")
				sys.exit(1)
			rules = section["rules"] 
			for rule_name in rules:
				process_rule(rule_name, rules_path, output_path, config, odv_level_items, custom_path, separate_fix, include_echo, config_profile_list_file, script_summary)

	else:
		process_all_rules(rules_path, output_path, config, odv_level_items, custom_path, separate_fix, include_echo, config_profile_list_file, script_summary)

	write_md_file(md_path, script_summary)

if __name__ == '__main__':
	main()