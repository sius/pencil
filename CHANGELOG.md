# Changelog

## Version 2.0.2
- SSHAPasswordEncoder supports unsalted SHA hashes with saltsize 0

## Version 2.0.1
- resolves critical bug from 2.0.0
- allow smaller saltsizes than 8 bytes to support unsalted hashes

## Version 2.0.0
- __DO NOT USE__ - critical bug leaks password hashes to stdout
- bug fix utf-8 encoding
- the autoconfiguration Property charset has been removed

## Version 1.1.0
- __DO NOT USE__ - UTF-8 encoding bug

## Version 1.0.0
- __DO NOT USE__ - UTF-8 encoding bug
- Initial Release
