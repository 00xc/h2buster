# Changelog #

## 0.3d ##
* A list of extensions can be given to be scanned, separated by a semicolon, with `-x`. For example, `-x '.php;.js;blank;/'` will check for .php, .js, blank and / file endings. Note that the `blank` keyword is used to signify no file ending.
* Improved target parsing (`-u`).
* Added feedback on stdout to see current entry being scanned (only on Linux and OS X).
* Changed default threads (`-t`) from 15 to 20.
* Improved color printing performance. The program should run smoother on both UNIX-based and Windows.
* Other very slight performance improvements.

## 0.3c-1 ##
* Fixed a bug where not using `-wc` on Windows would crash the program.
* Fixed a bug where found directories with a space on them would not be properly URL encoded when scanning them.

## 0.3c ##
* HTTP/2 support on the target is checked before starting scan. If the target is not compatible or resets connection, the program exits more gracefully.
* Added colors in output (only for Linux and OS X). To disable them, use `-nc`.

## 0.3b ##
* Fixed a bug where for some entries in the wordlist would crash the script.
* Improved directory detection for found entries:
	- Some found URLs ending in `/` are no longer classified as directories (such as `/index.php/`).
	- URLs ending in `//` are no longer considered directories.

## 0.3a ##
* Added multiprocessing. Each process handles its own HTTP/2 connection. Number of connections can be specified with `-c`. This should greatly improve speed.
* Improved target URL parsing. Scan can now start from a different directory than the root web directory. Use it as: `-u target_ip/starting_directory`.
* Now if `directory_depth` (`-r`) (previously known as `maximum_recursion`) is zero, there is no limit to directory recursion.
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