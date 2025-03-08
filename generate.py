#!/usr/bin/env python3
import logging
import optparse
import os
import sys
import urllib.error
import urllib.request

# ----------------------------------------
#                mSCP
# ----------------------------------------

# ----------------------------------------
#           Custom Baseline
# ----------------------------------------


# ----------------------------------------
#              Munki Items
# ----------------------------------------

# ----------------------------------------
#                 Main
# ----------------------------------------

def setup_logging():
	logging.basicConfig(
		level=logging.DEBUG,
		format="%(asctime)s - %(levelname)s (%(module)s): %(message)s",
		datefmt='%d/%m/%Y %H:%M:%S',
		stream=sys.stdout)

def main():
	setup_logging()

if __name__ == '__main__':
	main()