# Changelog #

## 0.3b ##
* Fixed a bug where for some entries in the wordlist would crash the script.
* Improved directory detection for found entries:
	- Some found URLs ending in `/` are no longer classified as directories (such as `/index.php/`)
	- URLs ending in `//` are no longer considered directories.

## 0.3a ##
* Added multiprocessing. Each process handles its own HTTP/2 connection. Number of connections can be specified with `-c`. This should greatly improve speed.
* Improved target URL parsing. Scan can now start from a different directory than the root web directory. Use it as: `-u target_ip/starting_directory`.
* Now if `directory_depth` (`-r`) is zero, there is no limit to directory recursion.
* Changed default threads from 10 to 15.
* Information printed at the start of the program is more complete and verbose.
* Added a small dumb dictionary to perform light tests at `/test/small.txt`.
* Cleaned up code: default values and help text are declared as constants at the beginning of the program.

## 0.2 ##
* Added multithreading with option `-t`.
* Updated target port infering logic based on input (will default to port 443 unless `http://` or `:80` are present).

## 0.1d ##
* Changed CLI inputs from positional to optional arguments.
* Added `maximum_recursion` as an option (`-r`).
* Added help for each option with `-h | --help`.
* Aborting scan now ensures that the connection is closed.

## 0.1c ##
* Redirection response codes are now indicated with text. Redirection locations are printed.
* Improved directory detection and results printing.
* Blank extension added.
* Minor performance fixes.
* Several updates to TODO file.

## 0.1b ##
* Implemented maximum recursion and added it as a hardcoded constant.
* Added a screen update parameter as a hardcoded constant.
* Fixed recursion for 301 responses.

## 0.1a ##
* Fixed error handling.
* Changed to recursive search instead of just a top-level scan.

## 0.1 ##
* Initial commit.