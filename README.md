STEP 1 STEP 1 STEP 1 STEP 1 STEP 1 STEP 1 STEP 1 STEP 1 STEP 1 STEP 1 STEP 1 STEP 1 STEP 1 STEP 1 
WinShield - Windows Vulnerability Scanner
Purpose:
  - Enumerate locally installed Windows KB updates
  - Pull the latest Microsoft Security Response Center (MSRC) monthly bulletin
  - Parse CVEs and map them to KB updates
  - Compare local KBs vs bulletin to identify missing patches
  - Print a readable report and save a JSON file for downstream hotfixing

Notes:
  - This module is read-only. It does not install anything.
  - Designed to work on older x86 images where standard cmdlets may return nothing.
"""