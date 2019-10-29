# Changelog #

## 0.4a ##
* Updated most strings to f-strings. **This makes Python 3.6 a requirement**.
* Added the option to scan for the robots.txt file (`-rb`):
	- If found, the user is prompted about whether to use its information or not.
	- The user can either retrieve all entries in the file, just the allowed ones based on our own User Agent, or completely ignore the file.
	- HOWEVER, dictionary entries **ARE NOT CHECKED** against the robots.txt rules. Use your wordlist at your own risk. I might add the option to only use dictionary entries if they are allowed as a command line option in the future.
	- The information obtained from this file can be used in a smarter way. For now all the directories found are checked in their respective recursive depth. The entry `/a/b/c` will result in checking `/a` in the first iteration. If `/a` is found, `/a/b` will be searched in the next recursive iteration. Repeat this process for `/a/b/c`.
* Reset HTTP/2 streams:
	- More information is given about the process which handles that stream.
	- Increased sleep time for the thread handling that reset.
* Removed an unnecessary include. The rest of the includes are now tidier.
* Duplicated entries in the input wordlist are just requested once.
* Increased modularity by moving parser algorithms to external classes.
* Removed the `enable_push` parameter for a call to the underlying hyper library - some versions don't seem to accept it.
* Changed the way time is benchmarked. Now it represents how much seconds the actual scan took (as opposed to the time of option parsing & checking + the scan).

## 0.3f ##
* Added an option to ignore specific response codes (`-b`) by providing a list of codes separated by a vertical bar (`|`). Default is 404.

## 0.3e-2 ##
* Improved error handling:
	- Now processes exit gracefully when things go wrong in the middle of a scan instead of hanging.
	- Keyboard interrupt is now less ugly.
* Changed default connections (`-c`) to 4. This seems to yield a performance improvement in most cases.
* Changed `--help` text to be tidier.
* Changed line endings to UNIX-style (in case you were trying to run as `./h2buster.py`).

## 0.3e-1 ##
* Improved error handling for non-RFC-compliant HTTP/2 servers.

## 0.3e ##
* A list of headers can be given to be sent for each request with `-hd` with the format `-hd 'header->value[|header->value|header->value...]'`. For example: `-hd 'user-agent->Mozilla/5.0|accept-encoding->gzip, deflate, br'`.
* Extensions are now separated by a vertical bar too (`|`) for consistency (e.g. `-x '.php|.js|blank|/'`).
* The `server` header of the first response is now displayed at the beginning of the scan (if there is one).

## 0.3d-1 ##
* Improved error handling for reset connections, HTTP/1-only targets, targets that do not exist and TLS errors.

## 0.3d ##
* A list of extensions can be given to be scanned, separated by a semicolon, with `-x`. For example, `-x '.php;.js;blank;/'` will check for .php, .js, blank and / file endings. Note that the `blank` keyword is used to signify no file ending.
* Improved target parsing (`-u`).
* Added feedback on stdout to see current entry being scanned (only on Linux and OS X).
* Changed default threads (`-t`) from 15 to 20.
* Improved color printing performance. The program should run smoother on both UNIX-based and Windows.
* Other very slight performance improvements.

## 0.3c-1 ##
* Fixed a bug where not using `-nc` on Windows would crash the program.
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