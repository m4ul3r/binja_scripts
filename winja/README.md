# winja

Merge the loaded modules (cached bndbs) into the currently debugged bndb. 

If the script is ran for the first time, it will load each dll into the session and save the bndb into `C:\Users\<user>\Documents\winja`. Running the script will take some time with merging the databases, especially on the initial run (to cache the bndbs).

Big thanks to [playoff-rondo](https://github.com/thisusernameistaken)

### Usage

1. Load in a target executable.
2. Set a breakpoint at any point of interest.
3. Start the debugger.
4. Continue to point of interest.
5. Run the script.
6. Now there is symbols and type information for the target modules.