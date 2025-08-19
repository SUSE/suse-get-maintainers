SUSE-GET-MAINTAINERS
====================


Overview
--------
suse-get-maintainers utility takes either a kernel path, an upstream
commmit hash, a unified patch produced by git or a CVE number and
produces contacts for SUSE maintainers responsible for the relevant
code. It can also work in a batch mode where the input is provided on
the standard input one item per a line and the results are presented
in CSV or JSON formats on stdout. For advanced functionality
(upstream hashs, CVE numbers) it requires access to a git kernel tree
and git kernel vulnerability database.

Experimental feature
--------------------
suse-add-cves is an experimental program for adding CVE and Bugzilla
references to SUSE Kernel patches.  It share code with
suse-get-maintainers.
