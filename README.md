# DirectoryImporter
This is a Burpsuite plugin built to enable you to import your directory bruteforcing results into burp for easy viewing later. This is an alternative to proxying bruteforcing tools through burp to catch the results.

It is modularized for easily adding parsing of different bruteforcing tools. An example for GoBuster and DirSearch are added to this repo.

It can also be found within the BApp store under Directory Importer!

# Module Creation

To create a new parser make a new class that extends BaseParser and implement the parseDirectory method which takes a line from the bruteforce tool output file and returns a URL for burpsuite to use. 
