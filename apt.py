command = ""
suornot = "$ "
password = "su"
from time import sleep
while command != "exit" or command != "apt" or command != "git" or command != "su" or command != "su 1":
    command = input(suornot)
    if command == "exit":
        exit()
    if command == "su":
        password = input("Password: ")
        if password == "su":
            sleep(0.5)
            suornot = "# "
        else:
            print("Wrong password.")
    if command == "su 1":
        sleep(0.5)
        suornot = "$ "
    if command == "apt" or command == "apt-get":
        sleep(0.5)
        print("apt 1.4.9 (x86-x64)")
        print("Usage: apt [options] command")
        print()
        print("apt is a commandline package manager and provides command for")
        print("searching and managing as well as querying information about packages.")
        print("It provides the same functionality as the specialized APT tools,")
        print("like apt-get and apt-cache, but enables options more suitable for")
        print("interactive use by default.")
        print("")
        print("Most used commands:")
        print("  list - list packages based on package names")
        print("  search - search in package descriptions")
        print("  show - show package details")
        print("  install - install packages")
        print("  remove - remove packages")
        print("  autoremove - Remove automatically all unused packages")
        print("  update - update list of available packages")
        print("  upgrade - upgrade the system by installing/upgrading packages")
        print("  full-upgrade - upgrade the system by removing/installing/upgrading packages")
        print("  edit-sources - edit the source information file")
        print()
        print("See apt(8) for more information about the available commands.")
        print("Configuration options and syntax id detailed in apt.conf(5).")
        print("Information about how to configure sources can be found in sources.list(5).")
        print("Package and version choises can be expressed via apt_preferences(5).")
        print("Security details are available in apt-secure(8).")
        print("                                         This APT has Super Cow Powers.")
    if command == "git":
        sleep(0.5)
        print("Usage: git [--version] [--help] [-C <path>] [-c <name>=<value>]")
        print("           [--exec-path[=<path>]] [--html-path] [--man-path] [--info-path]")
        print("           [-p | --paginate | -P | --no-pager] [--no-replace-objects] [--bare]")
        print("           [--git-dir=<path>] [--work-tree=<path>] [--namespace=<name>]")
        print("           <command> [<args>]")
        print("")
        print("The are common Git commands used in various situations:")
        print()
        print("start a working area (see also: git help tutorial)")
        print("  clone              Clone a repository into a new directory")
        print("  init               Create an empty Git repository or reinitialize an exsisting one")
        print("")
        print("work on the current change (see also: git help everyday)")
        print("  add                Add file contents to the index")
        print("  mv                 Move or rename a file, a directory, or a symlink")
        print("  restore            Restore working tree files")
        print("  rm                 Remove files from the working tree an dfrom the index")
        print("  sparse-checkout    Initialize and modify the sparse-checkout")
        print("")
        print("examine the history and state (see also: git help revisions)")
        print("  bisect             Use binary search to find the commit that introduced a bug")
        print("  diff               Show changes between commits, commit and working tree, etc")
        print("  grep               Print lines matching a pattern")
        print("  log                Show commit logs")
        print("  show               Show various types of objects")
        print("  status             Show the working tree status")
        print("")
        print("grow, mark and tweak your common history")
        print("  branch             List, create, or delete branches")
        print("  commit             Record changes to the repository")
        print("  merge              Join two or more deveolopment histories together")
        print("  rebase             Reapply commits on top of another base tip")
        print("  reset              Reset current HEAD to the specified state")
        print("  switch             Switch branches")
        print("  tag                Create, list, delete or verify a tag object signed with GPG")
        print("")
        print("collaborate (see also: git help workflows)")
        print("  fetch              Download objects and refs from another repository")
        print("  pull               Fetch from and integrate with another repository or a local branch")
        print("  push               Update remote refs along with associated objects")
        print("")
        print("'git help -a' and 'git help -g' list available subcommands and some")
        print("concept guides. See 'git help <command>' or 'git help <concept>'")
        print("to read about a specific subcommand or concept")
        print("See 'git help git' for an overview of the system")
    if command == "apt moo":
        print("                 (__)")
        print("                 (OO)")
        print("           /------\/")
        print("          / |     ||")
        print("         *  /\----/\ ")
        print("            ~~    ~~")
        print('..."Have you mooed today?"...')
    if command == "clear":
        print("\n"*100)