# Changelog #

## 0.2 ##
* Added multithreading with option `-t`.
* Updated target port infering logic based on input (will default to port 443 unless "http://" or ":80" are present).

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