#!/usr/bin/env python3
import datetime
# import importlib.util
import logging
import optparse
import os
import pathlib
import plistlib
# import runpy
import sys
import yaml

CONFIG_PATH = "config.yaml"
MD_PATH = "munki-mscp-generation-summary.md"
OUTPUT_PATH = "munki"

BASH_INDICATOR = "[source,bash]"
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

# # ----------------------------------------
# #              Rules
# # ----------------------------------------

def process_rule(rule, config, separate_fix, include_echo, mobileconfig_path, output_path, script_summary):
	note = None
	if "note:" in rule.discussion.lower():
		n = rule.discussion.lower().find("note:") 
		note = rule.discussion[n:].strip()
	if "warning:" in rule.discussion.lower():
		n = rule.discussion.lower().find("warning:") 
		note2 = rule.discussion[n:].strip()
		logging.warning(f"Rule {rule.rule_id} comes with the following warning:\n\t{note2}\n\tNote that despite the warning a munki item has been created for {rule.rule_id}. If you wish to remove this rule, please do so in the baseline.\n\n")
		if note:
			if len(note2) > len(note):
				note = note2
		else:
			note = note2
	if (rule.check and rule.result_value != None and rule.fix):
		create_munki_item(rule, config, separate_fix, include_echo, mobileconfig_path, output_path)
		script_summary["items_made"].append((rule.rule_id, note))
	elif rule.mobileconfig_info:
		if mobileconfig_path:
			create_munki_item(rule, config, separate_fix, include_echo, mobileconfig_path, output_path)
			script_summary["config_items_made"].append((rule.rule_id, rule.mobileconfig_info, note))
		else:
			script_summary["items_skipped"].append((rule.rule_id, rule.mobileconfig_info, note))
	else:
		if not note:
			note = ""
		script_summary["rules_no_fix"].append((rule.rule_id, f"The fix mechanism is {rule.mechanism}. \n{note}"))


# # ----------------------------------------
# #              Munki Items
# # ----------------------------------------

def create_munki_item(rule, config, separate_fix, include_echo, mobileconfig_path, output_path):
	item = dict()
	# name
	munki_item_name = get_munki_item_name(rule.rule_id, config)
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
			item[key] = getattr(rule, config["fields_from_rule"][key])
	# static keys
	if "static_fields" in config:
		for key in config["static_fields"]:
			item[key] = config["static_fields"][key]
	# check / fix
	# fix is with configuration profile
	if rule.mobileconfig_info and mobileconfig_path:
		if mobileconfig_path:
			add_write_to_mobileconfig_profile_file(item, rule.rule_id, mobileconfig_path, separate_fix, include_echo)
		else:
			logging.error("Trying to crate munki items for rules where fix must be implemented by a Configuration Profile but no mobileconfig_path is given. Something went wrong!")
			sys.exit(1)
	# fix is code
	else:
		add_check_fix_scripts(item, rule, separate_fix, include_echo, config["check_prefix"])
	# write
	write_munki_item(f"{munki_item_name_file_name}.plist", output_path, item)

def add_check_fix_scripts(item, rule, separate_fix, include_echo, check_prefix):
	prefix_code = ""
	if BASH_INDICATOR in rule.discussion:
		prefix_code = get_code_from_discussion(rule.discussion)
	check_prefix = (check_prefix + "\n" + prefix_code).rstrip("\n")
	if separate_fix:
		add_check_to_installcheck(item, rule, check_prefix, include_echo)
		add_fix_to_preinstall(item, rule, prefix_code, include_echo)
	else:
		add_check_and_fix_to_installcheck(item, rule, check_prefix, include_echo)

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

def create_check_strings(rule, prefix_code, include_echo):
	# store check variable
	prefix_code += f"\n\nresult_value=$({rule.check})\n"
	# compare to expected result
	comparison = f"[[ $result_value != \"{rule.result_value}\" ]]"
	# suffix
	else_script = None
	if include_echo:
		else_script = "echo \"No fix needed\""
	return prefix_code, comparison, else_script
	
def add_check_and_fix_to_installcheck(item, rule, prefix_code, include_echo):
	# store check variable, compare to expected result and get optional echo if no fix needed
	prefix_code, comparison, else_script = create_check_strings(rule, prefix_code, include_echo)
	# fix
	fix = create_bash_fix_str(rule, include_echo)
	# write script
	item["installcheck_script"] = create_if_else_script(SHEBANG_BASH, prefix_code, comparison, fix, else_script)

def add_check_to_installcheck(item, rule, prefix_code, include_echo):
	# store check variable and compare to expected result
	prefix_code, comparison, else_script = create_check_strings(rule, prefix_code, include_echo)
	# fix
	if_script = "exit 0"
	# write script
	item["installcheck_script"] = create_if_else_script(SHEBANG_BASH, prefix_code, comparison, if_script, else_script)

def add_fix_to_preinstall(item, rule, prefix_code, include_echo):
	# prefix
	s = SHEBANG_BASH 
	# add prefix code
	s += prefix_code + "\n"
	# fix
	s += create_bash_fix_str(rule, include_echo)
	item["preinstall_script"] = s

def create_bash_fix_str(rule, include_echo):
	result = "" 
	if include_echo:
		result += 'echo "Applying fix"\n'
	result += rule.fix
	return result

def add_write_to_mobileconfig_profile_file(item, name, path, separate_fix, include_echo):
	add_config_profile_for_install(item, name, path, separate_fix, include_echo)
	add_config_profile_for_uninstall(item, name, path, include_echo)


def add_config_profile_for_install(item, name, path, separate_fix, include_echo):
	prefix = f'PLIST_PATH="{path}"\n\n'
	prefix2 = f"/usr/libexec/PlistBuddy -c 'Print :RequestedRules' $PLIST_PATH | /usr/bin/grep -qE '^\\s+{name}$'\n"
	comp = "[[ ! $? ]]"
	fix = ""
	else_script = None
	if include_echo:
			fix += "echo \"Adding to plist file\"\n"
			else_script = "echo \"Already in plist file\"\n"
	fix += "/usr/libexec/PlistBuddy -c 'Add :RequestedRules array' $PLIST_PATH\n"
	fix += f"/usr/libexec/PlistBuddy -c 'Add :RequestedRules: string {name}' $PLIST_PATH\n"
	if separate_fix:
		item["installcheck_script"] = create_if_else_script(SHEBANG_ZSH, prefix + prefix2, comp, "exit 0", else_script)
		item["preinstall_script"] = SHEBANG_ZSH + prefix + fix
	else:
		item["installcheck_script"] = create_if_else_script(SHEBANG_ZSH, prefix + prefix2, comp, fix, else_script)

def add_config_profile_for_uninstall(item, name, path, include_echo):
	if "autoremove" not in item:
		item["autoremove"] = True
	if "unattended_uninstall" not in item:
		item["unattended_uninstall"] = True
	if "uninstall_method" not in item:
		item["uninstall_method"] = "uninstall_script"

	# uninstall
	prefix = f'PLIST_PATH="{path}"\n\n'
	# get number of times item in rules
	prefix2 = f'requested_rule=$(/usr/libexec/PlistBuddy -c "Print :RequestedRules" $PLIST_PATH | /usr/bin/grep -n -E "^\\s+{name}$" | /usr/bin/awk -F ":" \'{"{print $1}"}\')\n'
	# if 1 then remove it
	comp = '[ ! -z "$requested_rule" ]'
	# remove it
	remove = '# Item to delete is the number minus two\nitemToDelete=$(($requested_rule-2))\n/usr/libexec/PlistBuddy -c "Delete :RequestedRules:$itemToDelete" $PLIST_PATH\n'
	if include_echo:
		remove += 'echo "Removed from plist file"\n'
	# else do nothing
	else_script = None
	if include_echo:
		else_script = 'echo "Item already removed from plist file - nothing to do"\n'
	item["uninstall_script"] = create_if_else_script(SHEBANG_ZSH, prefix + prefix2, comp, remove, else_script, False)

	# uninstall check
	prefix3 = f'/usr/libexec/PlistBuddy -c \'Print :RequestedRules\' $PLIST_PATH | grep -qE "^\\s+{name}$"\n'
	item["uninstallcheck_script"] = create_if_else_script(SHEBANG_ZSH, prefix + prefix3,  "[[ $? ]]", "exit 0", None)

def get_munki_item_name(name, config):
	name = name.replace("_", config["delimiter"])
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
			if (s.endswith(f"{BASH_INDICATOR}\n") or s.endswith(f"{BASH_INDICATOR}")) and i < len(chunks)-1:
				result += chunks[i+1].lstrip(" \n").rstrip(" \n")
				result += "\n"
	return result

def write_munki_item(name, output_path, item):
	item_path = os.path.join(output_path, name)
	# open file
	with open(item_path, "wb+") as file:
		try:
			# make sure we are at start of file
			file.seek(0)
			# write to file
			plistlib.dump(item, file, fmt=plistlib.FMT_XML, sort_keys=False)
			# remove any excess of old file
			file.truncate()
		except Exception as e:
			logging.error(f"Could not write to file {item_path} in munki directory.")
			logging.error(e, exc_info=True)
			sys.exit(1)

# # ----------------------------------------
# #                Config 
# # ----------------------------------------
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
		if set(keys).issubset({"fields_from_rule", "static_fields", "metadata", "prefix", "suffix", "version", "delimiter", "mobileconfig_file", "check_prefix"}):
			for key in keys:
				if key in ["prefix", "suffix", "delimiter", "mobileconfig_file", "check_prefix"]:
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
		else:
			logging.error(f'Unknown key(s) in config file: {str(set(keys).difference({"fields_from_rule", "static_fields", "metadata", "prefix", "suffix"}))[1 : -1]}. Please update config file.')
			sys.exit(1)
	else:
		logging.error(f"Unexpected format of config file. Expected file in the format of dictionary, but indtead file is formatted as {type(config)}. Please update config file.")
		sys.exit(1)
	return True

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
	if "check_prefix" not in config:
		config["check_prefix"] = ""
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

def update_mobileconfig_path(path, config):
	if path:
		return path
	if "mobileconfig_file" not in config:
		return None
	return config["mobileconfig_file"]

# # ----------------------------------------
# #                Markdown
# # ----------------------------------------
def write_md_file(md_file, script_summary):
	md = md_description(script_summary)
	write_file(md_file, md)
	logging.info("Markdown file successfully updated.")

def md_add_note(s, note):
	if note:
		for line in note.splitlines():
			if line.startswith("*"):
				s += f"        * {line[1:]}\n"

			elif line.strip() != "":
				s += f"    * {line}\n"
	return s

def md_add_mobileconfig_descr(s, info):
	for mobileconfigpayload in info:
		s += f"    * In preference domain {mobileconfigpayload.payload_type}:\n"
		for d in mobileconfigpayload.payload_content:
			for key in d:
				s += f"        * `{key}` must be set to `{d[key]}`\n"
	return s


def md_description(script_summary):
	s = "# Summary of munki items generated by munki-mscp-generator\n\n"

	s += '## Generated Items\n\n'

	if len(script_summary["items_made"]) > 0:
		s += "### Generated munki items for the following rules where fixes are implemented with a script:\n"
		for name, note in script_summary["items_made"]:
			s += f"* {name}\n"
			s = md_add_note(s, note)
		s += "\n\n"

	if len(script_summary["config_items_made"]) > 0:
		s += "### Generated munki items for the following rules where fixes must be implemented by a Configuration Profile:\n"
		for name, info, note in script_summary["config_items_made"]:
			s += f"* {name}\n"
			s = md_add_note(s, note)
			s = md_add_mobileconfig_descr(s, info)
		s += "\n\n"

	if len(script_summary["items_made"]) + len(script_summary["items_skipped"]) < 1:
		s += "No munki items generated.\n\n"

	if len(script_summary["items_skipped"]) + len(script_summary["rules_no_fix"]) > 0:
		s += '## Skipped Items\n\n'

		if len(script_summary["items_skipped"]) > 0:
			s += "### The following rules were skipped as they have fixes that must be implemented by a Configuration Profile:\n"
			for name, info, note in script_summary["items_skipped"]:
				s += f"* {name}\n"
				s = md_add_note(s, note)
				s = md_add_mobileconfig_descr(s, info)
			s += "\n\n"

		if len(script_summary["rules_no_fix"]) > 0:
			s += "### The following rules had no defined fix, so were skipped:\n* "
			for name, note in script_summary["rules_no_fix"]:
				s += f"* {name}\n"
				s = md_add_note(s, note)
			s += "\n\n"

	s = s.replace("&", "\&")
	s = s.replace("[", "\[")
	s = s.replace("<", "\<")
	s = s.replace("]\n    * `\n    *", "\\<")
	s = s.replace("----", "\----")
	return s

# # ----------------------------------------
# #           mSCP imports
# # ----------------------------------------
def update_mscp_config(path):
	global original_mscp_config
	mscp_config_path = os.path.join(path, "src/mscp/data/config.yaml")
	original_mscp_config = read_file(mscp_config_path)
	mscp_config = read_yaml(mscp_config_path)
	mscp_config["custom_dir"] = str(os.path.join(path, mscp_config["custom_dir"])) 
	# update_mscp_config_dict(mscp_config, path)
	write_yaml(mscp_config_path, mscp_config)

# def update_mscp_config_dict(d, path):
# 	for k in d:
# 		if isinstance(d[k], str):
# 			if k.endswith("config") or k.endswith("dir") or k.endswith("data") or k.endswith("file"):
# 				d[k] = str(os.path.join(path, d[k])) 
# 		elif isinstance(d[k], dict):
# 			update_mscp_config_dict(d[k], path)

def mscp_imports(path):
	global Baseline
	update_mscp_config(path)
	try:
		sys.path.append(os.path.abspath(path))
		logging.info("Importing from mSCP directory...")
		from src.mscp.classes.baseline import Baseline
		logging.info("Successfully finished importing from mSCP directory.")
	except Exception as e:
		logging.error(f"Unable to import necessary classes from {path}. This directory should correspond to https://github.com/usnistgov/macos_security.")
		logging.error(e, exc_info=True)
		sys.exit(1)

def revert_mscp_config(path):
	write_file(os.path.join(path, "src/mscp/data/config.yaml"), original_mscp_config)


# # ----------------------------------------
# #           Helper functions
# # ----------------------------------------
def read_yaml(path) -> dict:
	if not os.access(path, os.R_OK):
		logging.error(f"No access to {path}")
		sys.exit(1)	
	with open(path, "rb") as file_yaml:
		try:
			result = yaml.safe_load(file_yaml)
			return result
		except yaml.YAMLError as e:
			logging.error(f"Unable to load {path}")
			logging.error(e, exc_info=True)
			sys.exit(1)

def write_yaml(path, d):
	if not os.access(path, os.W_OK):
		logging.error(f"No write access to {path}")
		sys.exit(1)	
	with open(path, "w") as file:
		try:
			yaml.dump(d, file, default_flow_style=False, explicit_start=True)
		except Exception as e:
			logging.error(f"Unable to write to {path}")
			logging.error(e, exc_info=True)
			sys.exit(1) 

def read_file(path):
	if not os.access(path, os.R_OK):
		logging.error(f"No access to {path}")
		sys.exit(1)	
	with open(path, 'r') as file:
		try:
			result = file.read()
			return result
		except Exception as e:
			logging.error(f"Unable to read {path}")
			logging.error(e, exc_info=True)
			sys.exit(1)

def write_file(path, s):
	if not os.access(path, os.W_OK):
		logging.error(f"No write access to {path}")
		sys.exit(1)	
	with open(path, "w") as file:
		try:
			file.seek(0)
			file.write(s)
			file.truncate()
		except Exception as e:
			logging.error(f"Unable to write to {path}")
			logging.error(e, exc_info=True)
			sys.exit(1) 


def setup_logging():
	logging.basicConfig(
		level=logging.DEBUG,
		format="%(asctime)s - %(levelname)s (%(module)s): %(message)s",
		datefmt='%d/%m/%Y %H:%M:%S',
		stream=sys.stdout)

def check_path(path, s, flag):
	if not path:
		logging.error(f"No path to the {s} given. Please provide this with {flag}.")
		sys.exit(1)
	if not os.path.exists(path):
		logging.error(f"Provided path to the {s} does not exist. Please provide the path with {flag}.")
		logging.error(f"Path provided: {path}")
		sys.exit(1)

# # ----------------------------------------
# #                 Main
# # ----------------------------------------

def process_options():
	parser = optparse.OptionParser()
	parser.set_usage("Usage: %prog [options]")
	parser.add_option("--mscp_dir", "-m", dest="mscp_path",
						help="Path to the mscp dir https://github.com/usnistgov/macos_security. Will use rules, baselines and customs found in this dir if paths are not otherwise specified.")
	parser.add_option("--baseline-path", "-b", dest="baseline_path",
						help="Path to baseline yaml file.")
	parser.add_option("--config", "-c", dest="config_path",
						help=f"Optional path to the configuration yaml file, which specifies values for the munki item. Defaults to {CONFIG_PATH}")
	parser.add_option("--outputdir", "-o", dest="output_path", default=OUTPUT_PATH,
						help=f"Optional path to the directory generated munki files should be written to. Defaults to {OUTPUT_PATH}")
	parser.add_option("--prefix", dest="prefix",
						help=f"Optional prefix to add to the name of every generated munki item and it's file name.")
	parser.add_option("--suffix", dest="suffix",
						help=f"Optional suffix to add to the name of every generated munki item and it's file name.")
	parser.add_option("--version", "-v", dest="version",
						help=f"Optional version to be set in every munki item and appended to the name of every generated munki item. Specifying a version here will override a version given in the configuration yaml file.")
	parser.add_option("--separate", "-s", dest="separate_fix", action="store_true",
						help="Write fix script in preinstall_script, rather than in installcheck_script.")
	parser.add_option("--no-munki-output", dest="no_echo", action="store_true",
						help="Prevent munki items from using echo statements to log their checks and fixes.")
	parser.add_option("--mobileconfig-file", dest="mobileconfig_path",
						help="Optional path to the file where munki items will write to if their fix can only be implemented by a configuration profile. Specifying a file path here will override a file given in the configuration yaml file.")
	parser.add_option("--markdown", dest="md_path", default=MD_PATH,
						help=f"Optional file name to print markdown summary of how the rules were processed by this script. Defaults to {MD_PATH}")
	options, _ = parser.parse_args()
	check_path(options.mscp_path, "mSCP directory", "-m or -mscp_dir")
	check_path(options.baseline_path, "baseline yaml file", "-b or -baseline_path")
	return options.mscp_path, options.baseline_path, options.config_path, options.output_path, options.prefix, options.suffix, options.version, options.separate_fix, not options.no_echo, options.mobileconfig_path, options.md_path


def main():
	setup_logging()

	mscp_path, baseline_path, config_path, output_path, prefix, suffix, version, separate_fix, include_echo, mobileconfig_path, md_path = process_options()
	# get config
	config = get_config(config_path, prefix, suffix, version)
	# update mobileconfig_path from config
	mobileconfig_path = update_mobileconfig_path(mobileconfig_path, config)
	# output dir
	prep_munki_item_dir(output_path)
	# prep summary
	script_summary = {"items_made":[], "config_items_made":[], "items_skipped":[], "rules_no_fix":[]}
	# import clases
	mscp_imports(mscp_path)

	# process relevant rules
	check_path(baseline_path, "baseline yaml file", "-b or -baseline_path")
	logging.info("Loading baseline...")
	baseline = Baseline.from_yaml(pathlib.Path(baseline_path), custom=True)
	logging.info("Successfully loaded baseline.")
	for profile in baseline.profile:
		for rule in profile.rules:
			process_rule(rule, config, separate_fix, include_echo, mobileconfig_path, output_path, script_summary)
	# summarise job
	write_md_file(md_path, script_summary)

	# change mscp dir back to original state
	revert_mscp_config(mscp_path)


if __name__ == "__main__":
	main()