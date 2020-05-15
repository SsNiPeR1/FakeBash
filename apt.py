def tt(text, delay):
    for i in text:
        print(end = i)
        time.sleep(delay)
    print()
command = ""
suornot = "$ "
password = "su"
chosenpassword = ""
import time
import hashlib
from os import listdir
from os import system
from os.path import isfile, join
while command != "exit" or command != "apt" or command != "git" or command != "su" or command != "sha256" or command != "md5" or command != "su 1" or command == "ls" or command != "yes" or command != "crunch" or command != 'curl' or command!= 'curl --help' or command != 'curl --manual' or command != "msfconsole" or command != "wget" or command != "wget --help":
    command = input(suornot)
    if command == "exit":
        exit()
    if command == "su":
        chosenpassword = input("Password (default is 'su', if you not changed it): ")
        if chosenpassword == "su":
            time.sleep(0.5)
            suornot = "# "
    if command == "md5":
        encode = input("Enter what you would like to hash: ")
        hash_object = hashlib.md5(encode.encode())
        print(hash_object.hexdigest())
    if command == "su 1":
        time.sleep(0.5)
        suornot = "$ "
    if command == "ls":
        onlyfiles = [f for f in listdir("./") if isfile(join("./", f))]
        print(onlyfiles)
    if command == "apt" or command == "apt-get":
        time.sleep(0.5)
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
    if command == "sha256":
        hashobject = input("Enter what you would like to hash:")
        hash_object = hashlib.sha256(hashobject.encode())
        hex_dig = hash_object.hexdigest()
        print(hex_dig)
    if command == "git":
        time.sleep(0.5)
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
    if command == "yes":
        whattoprint = input()
        while True:
            print(whattoprint)
            time.sleep(0.01)
    if command == "crunch":
        minnumber = int(input("min number:"))
        maxnumber = int(input("max number:"))
        if maxnumber >= minnumber:
            while minnumber != maxnumber:
                print(minnumber)
                minnumber += 1
                time.sleep(0.01)
        else:
            print("Min number is bigger than max number.")
    if command == "msfconsole":
        print("[*] Starting the Metasploit Framefork console...")
        time.sleep(10)
        print('')
        print('MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM')
        print('MMMMMMMMMMM                MMMMMMMMMM')
        print('MMMN$                           vMMMM')
        print("MMMMl  MMMMM             MMMMM  JMMMM")
        print("MMMMl  MMMMMMMN       NMMMMMMM  JMMMM")
        print("MMMMl  MMMMMMMMMNmmmNMMMMMMMMM  JMMMM")
        print("MMMMI  MMMMMMMMMMMMMMMMMMMMMMM  jMMMM")
        print("MMMMI  MMMMMMMMMMMMMMMMMMMMMMM  jMMMM")
        print("MMMMI  MMMMM   MMMMMMM   MMMMM  jMMMM")
        print("MMMMI  MMMMM   MMMMMMM   MMMMM  jMMMM")
        print("MMMMI  MMMMM   MMMMMMM   MMMMM  jMMMM")
        print("MMMMI  MMMMM   MMMMMMM   MMMMM  jMMMM")
        print("MMMMR  ?MMNM             MMMMM .dMMMM")
        print("MMMMNm `?MMM             MMMM` dMMMMM")
        print("MMMMMMN  ?MM             MM?  NMMMMMN")
        print("MMMMMMMMNe                 JMMMMMNMMM")
        print("MMMMMMMMMMNm,            eMMMMMNMMNMM")
        print("MMMMNNMNMMMMMNx        MMMMMMNMMNMMNM")
        print("MMMMMMMMNMMNMMMMm+..+MMNMMNMNMMNMMNMM")
    if command == "wget":
        print("wget: missing URL")
        print("Usage: wget [OPTION]... [URL]...")
        print()
        print("Try `wget --help' for more options.")
    if command == "wget --help":
        print('''GNU Wget 1.11.4, a non-interactive network retriever.
Usage: wget [OPTION]... [URL]...

Mandatory arguments to long options are mandatory for short options too.

Startup:
  -V,  --version           display the version of Wget and exit.
  -h,  --help              print this help.
  -b,  --background        go to background after startup.
  -e,  --execute=COMMAND   execute a `.wgetrc'-style command.

Logging and input file:
  -o,  --output-file=FILE    log messages to FILE.
  -a,  --append-output=FILE  append messages to FILE.
  -d,  --debug               print lots of debugging information.
  -q,  --quiet               quiet (no output).
  -v,  --verbose             be verbose (this is the default).
  -nv, --no-verbose          turn off verboseness, without being quiet.
  -i,  --input-file=FILE     download URLs found in FILE.
  -F,  --force-html          treat input file as HTML.
  -B,  --base=URL            prepends URL to relative links in -F -i file.

Download:
  -t,  --tries=NUMBER            set number of retries to NUMBER (0 unlimits).
       --retry-connrefused       retry even if connection is refused.
  -O,  --output-document=FILE    write documents to FILE.
  -nc, --no-clobber              skip downloads that would download to
                                 existing files.
  -c,  --continue                resume getting a partially-downloaded file.
       --progress=TYPE           select progress gauge type.
  -N,  --timestamping            don't re-retrieve files unless newer than
                                 local.
  -S,  --server-response         print server response.
       --spider                  don't download anything.
  -T,  --timeout=SECONDS         set all timeout values to SECONDS.
       --dns-timeout=SECS        set the DNS lookup timeout to SECS.
       --connect-timeout=SECS    set the connect timeout to SECS.
       --read-timeout=SECS       set the read timeout to SECS.
  -w,  --wait=SECONDS            wait SECONDS between retrievals.
       --waitretry=SECONDS       wait 1..SECONDS between retries of a retrieval.
       --random-wait             wait from 0...2*WAIT secs between retrievals.
       --no-proxy                explicitly turn off proxy.
  -Q,  --quota=NUMBER            set retrieval quota to NUMBER.
       --bind-address=ADDRESS    bind to ADDRESS (hostname or IP) on local host.
       --limit-rate=RATE         limit download rate to RATE.
       --no-dns-cache            disable caching DNS lookups.
       --restrict-file-names=OS  restrict chars in file names to ones OS allows.
       --ignore-case             ignore case when matching files/directories.
       --user=USER               set both ftp and http user to USER.
       --password=PASS           set both ftp and http password to PASS.

Directories:
  -nd, --no-directories           don't create directories.
  -x,  --force-directories        force creation of directories.
  -nH, --no-host-directories      don't create host directories.
       --protocol-directories     use protocol name in directories.
  -P,  --directory-prefix=PREFIX  save files to PREFIX/...
       --cut-dirs=NUMBER          ignore NUMBER remote directory components.

HTTP options:
       --http-user=USER        set http user to USER.
       --http-password=PASS    set http password to PASS.
       --no-cache              disallow server-cached data.
  -E,  --html-extension        save HTML documents with `.html' extension.
       --ignore-length         ignore `Content-Length' header field.
       --header=STRING         insert STRING among the headers.
       --max-redirect          maximum redirections allowed per page.
       --proxy-user=USER       set USER as proxy username.
       --proxy-password=PASS   set PASS as proxy password.
       --referer=URL           include `Referer: URL' header in HTTP request.
       --save-headers          save the HTTP headers to file.
  -U,  --user-agent=AGENT      identify as AGENT instead of Wget/VERSION.
       --no-http-keep-alive    disable HTTP keep-alive (persistent connections).
       --no-cookies            don't use cookies.
       --load-cookies=FILE     load cookies from FILE before session.
       --save-cookies=FILE     save cookies to FILE after session.
       --keep-session-cookies  load and save session (non-permanent) cookies.
       --post-data=STRING      use the POST method; send STRING as the data.
       --post-file=FILE        use the POST method; send contents of FILE.
       --content-disposition   honor the Content-Disposition header when
                               choosing local file names (EXPERIMENTAL).
       --auth-no-challenge     Send Basic HTTP authentication information
                               without first waiting for the server's
                               challenge.

HTTPS (SSL/TLS) options:
       --secure-protocol=PR     choose secure protocol, one of auto, SSLv2,
                                SSLv3, and TLSv1.
       --no-check-certificate   don't validate the server's certificate.
       --certificate=FILE       client certificate file.
       --certificate-type=TYPE  client certificate type, PEM or DER.
       --private-key=FILE       private key file.
       --private-key-type=TYPE  private key type, PEM or DER.
       --ca-certificate=FILE    file with the bundle of CA's.
       --ca-directory=DIR       directory where hash list of CA's is stored.
       --random-file=FILE       file with random data for seeding the SSL PRNG.
       --egd-file=FILE          file naming the EGD socket with random data.

FTP options:
       --ftp-user=USER         set ftp user to USER.
       --ftp-password=PASS     set ftp password to PASS.
       --no-remove-listing     don't remove `.listing' files.
       --no-glob               turn off FTP file name globbing.
       --no-passive-ftp        disable the "passive" transfer mode.
       --retr-symlinks         when recursing, get linked-to files (not dir).
       --preserve-permissions  preserve remote file permissions.

Recursive download:
  -r,  --recursive          specify recursive download.
  -l,  --level=NUMBER       maximum recursion depth (inf or 0 for infinite).
       --delete-after       delete files locally after downloading them.
  -k,  --convert-links      make links in downloaded HTML point to local files.
  -K,  --backup-converted   before converting file X, back up as X.orig.
  -m,  --mirror             shortcut for -N -r -l inf --no-remove-listing.
  -p,  --page-requisites    get all images, etc. needed to display HTML page.
       --strict-comments    turn on strict (SGML) handling of HTML comments.

Recursive accept/reject:
  -A,  --accept=LIST               comma-separated list of accepted extensions.
  -R,  --reject=LIST               comma-separated list of rejected extensions.
  -D,  --domains=LIST              comma-separated list of accepted domains.
       --exclude-domains=LIST      comma-separated list of rejected domains.
       --follow-ftp                follow FTP links from HTML documents.
       --follow-tags=LIST          comma-separated list of followed HTML tags.
       --ignore-tags=LIST          comma-separated list of ignored HTML tags.
  -H,  --span-hosts                go to foreign hosts when recursive.
  -L,  --relative                  follow relative links only.
  -I,  --include-directories=LIST  list of allowed directories.
  -X,  --exclude-directories=LIST  list of excluded directories.
  -np, --no-parent                 don't ascend to the parent directory.

Mail bug reports and suggestions to <bug-wget@gnu.org>.''')
    if command == "curl":
        print("curl: try 'curl --help' or 'curl --manual' for more information")
    if command == "curl --help" or command == "curl --manual":
        print('''curl --help
Usage: curl [options...] <url>
     --abstract-unix-socket <path> Connect via abstract Unix domain socket
     --alt-svc <file name> Enable alt-svc with this cache file
     --anyauth       Pick any authentication method
 -a, --append        Append to target file when uploading
     --basic         Use HTTP Basic Authentication
     --cacert <file> CA certificate to verify peer against
     --capath <dir>  CA directory to verify peer against
 -E, --cert <certificate[:password]> Client certificate file and password
     --cert-status   Verify the status of the server certificate
     --cert-type <type> Certificate file type (DER/PEM/ENG)
     --ciphers <list of ciphers> SSL ciphers to use
     --compressed    Request compressed response
     --compressed-ssh Enable SSH compression
 -K, --config <file> Read config from a file
     --connect-timeout <seconds> Maximum time allowed for connection
     --connect-to <HOST1:PORT1:HOST2:PORT2> Connect to host
 -C, --continue-at <offset> Resumed transfer offset
 -b, --cookie <data|filename> Send cookies from string/file
 -c, --cookie-jar <filename> Write cookies to <filename> after operation
     --create-dirs   Create necessary local directory hierarchy
     --crlf          Convert LF to CRLF in upload
     --crlfile <file> Get a CRL list in PEM format from the given file
 -d, --data <data>   HTTP POST data
     --data-ascii <data> HTTP POST ASCII data
     --data-binary <data> HTTP POST binary data
     --data-raw <data> HTTP POST data, '@' allowed
     --data-urlencode <data> HTTP POST data url encoded
     --delegation <LEVEL> GSS-API delegation permission
     --digest        Use HTTP Digest Authentication
 -q, --disable       Disable .curlrc
     --disable-eprt  Inhibit using EPRT or LPRT
     --disable-epsv  Inhibit using EPSV
     --disallow-username-in-url Disallow username in url
     --dns-interface <interface> Interface to use for DNS requests
     --dns-ipv4-addr <address> IPv4 address to use for DNS requests
     --dns-ipv6-addr <address> IPv6 address to use for DNS requests
     --dns-servers <addresses> DNS server addrs to use
     --doh-url <URL> Resolve host names over DOH
 -D, --dump-header <filename> Write the received headers to <filename>
     --egd-file <file> EGD socket path for random data
     --engine <name> Crypto engine to use
     --etag-save <file> Get an ETag from response header and save it to a FILE
     --etag-compare <file> Get an ETag from a file and send a conditional request
     --expect100-timeout <seconds> How long to wait for 100-continue
 -f, --fail          Fail silently (no output at all) on HTTP errors
     --fail-early    Fail on first transfer error, do not continue
     --false-start   Enable TLS False Start
 -F, --form <name=content> Specify multipart MIME data
     --form-string <name=string> Specify multipart MIME data
     --ftp-account <data> Account data string
     --ftp-alternative-to-user <command> String to replace USER [name]
     --ftp-create-dirs Create the remote dirs if not present
     --ftp-method <method> Control CWD usage
     --ftp-pasv      Use PASV/EPSV instead of PORT
 -P, --ftp-port <address> Use PORT instead of PASV
     --ftp-pret      Send PRET before PASV
     --ftp-skip-pasv-ip Skip the IP address for PASV
     --ftp-ssl-ccc   Send CCC after authenticating
     --ftp-ssl-ccc-mode <active/passive> Set CCC mode
     --ftp-ssl-control Require SSL/TLS for FTP login, clear for transfer
 -G, --get           Put the post data in the URL and use GET
 -g, --globoff       Disable URL sequences and ranges using {} and []
     --happy-eyeballs-timeout-ms <milliseconds> How long to wait in milliseconds for IPv6 before trying IPv4
     --haproxy-protocol Send HAProxy PROXY protocol v1 header
 -I, --head          Show document info only
 -H, --header <header/@file> Pass custom header(s) to server
 -h, --help          This help text
     --hostpubmd5 <md5> Acceptable MD5 hash of the host public key
     --http0.9       Allow HTTP 0.9 responses
 -0, --http1.0       Use HTTP 1.0
     --http1.1       Use HTTP 1.1
     --http2         Use HTTP 2
     --http2-prior-knowledge Use HTTP 2 without HTTP/1.1 Upgrade
     --http3         Use HTTP v3
     --ignore-content-length Ignore the size of the remote resource
 -i, --include       Include protocol response headers in the output
 -k, --insecure      Allow insecure server connections when using SSL
     --interface <name> Use network INTERFACE (or address)
 -4, --ipv4          Resolve names to IPv4 addresses
 -6, --ipv6          Resolve names to IPv6 addresses
 -j, --junk-session-cookies Ignore session cookies read from file
     --keepalive-time <seconds> Interval time for keepalive probes
     --key <key>     Private key file name
     --key-type <type> Private key file type (DER/PEM/ENG)
     --krb <level>   Enable Kerberos with security <level>
     --libcurl <file> Dump libcurl equivalent code of this command line
     --limit-rate <speed> Limit transfer speed to RATE
 -l, --list-only     List only mode
     --local-port <num/range> Force use of RANGE for local port numbers
 -L, --location      Follow redirects
     --location-trusted Like --location, and send auth to other hosts
     --login-options <options> Server login options
     --mail-auth <address> Originator address of the original email
     --mail-from <address> Mail from this address
     --mail-rcpt <address> Mail to this address
     --mail-rcpt-allowfails Allow RCPT TO command to fail for some recipients
 -M, --manual        Display the full manual
     --max-filesize <bytes> Maximum file size to download
     --max-redirs <num> Maximum number of redirects allowed
 -m, --max-time <seconds> Maximum time allowed for the transfer
     --metalink      Process given URLs as metalink XML file
     --negotiate     Use HTTP Negotiate (SPNEGO) authentication
 -n, --netrc         Must read .netrc for user name and password
     --netrc-file <filename> Specify FILE for netrc
     --netrc-optional Use either .netrc or URL
 -:, --next          Make next URL use its separate set of options
     --no-alpn       Disable the ALPN TLS extension
 -N, --no-buffer     Disable buffering of the output stream
     --no-keepalive  Disable TCP keepalive on the connection
     --no-npn        Disable the NPN TLS extension
     --no-progress-meter Do not show the progress meter
     --no-sessionid  Disable SSL session-ID reusing
     --noproxy <no-proxy-list> List of hosts which do not use proxy
     --ntlm          Use HTTP NTLM authentication
     --ntlm-wb       Use HTTP NTLM authentication with winbind
     --oauth2-bearer <token> OAuth 2 Bearer Token
 -o, --output <file> Write to file instead of stdout
 -Z, --parallel      Perform transfers in parallel
     --parallel-immediate Do not wait for multiplexing (with --parallel)
     --parallel-max  Maximum concurrency for parallel transfers
     --pass <phrase> Pass phrase for the private key
     --path-as-is    Do not squash .. sequences in URL path
     --pinnedpubkey <hashes> FILE/HASHES Public key to verify peer against
     --post301       Do not switch to GET after following a 301
     --post302       Do not switch to GET after following a 302
     --post303       Do not switch to GET after following a 303
     --preproxy [protocol://]host[:port] Use this proxy first
 -#, --progress-bar  Display transfer progress as a bar
     --proto <protocols> Enable/disable PROTOCOLS
     --proto-default <protocol> Use PROTOCOL for any URL missing a scheme
     --proto-redir <protocols> Enable/disable PROTOCOLS on redirect
 -x, --proxy [protocol://]host[:port] Use this proxy
     --proxy-anyauth Pick any proxy authentication method
     --proxy-basic   Use Basic authentication on the proxy
     --proxy-cacert <file> CA certificate to verify peer against for proxy
     --proxy-capath <dir> CA directory to verify peer against for proxy
     --proxy-cert <cert[:passwd]> Set client certificate for proxy
     --proxy-cert-type <type> Client certificate type for HTTPS proxy
     --proxy-ciphers <list> SSL ciphers to use for proxy
     --proxy-crlfile <file> Set a CRL list for proxy
     --proxy-digest  Use Digest authentication on the proxy
     --proxy-header <header/@file> Pass custom header(s) to proxy
     --proxy-insecure Do HTTPS proxy connections without verifying the proxy
     --proxy-key <key> Private key for HTTPS proxy
     --proxy-key-type <type> Private key file type for proxy
     --proxy-negotiate Use HTTP Negotiate (SPNEGO) authentication on the proxy
     --proxy-ntlm    Use NTLM authentication on the proxy
     --proxy-pass <phrase> Pass phrase for the private key for HTTPS proxy
     --proxy-pinnedpubkey <hashes> FILE/HASHES public key to verify proxy with
     --proxy-service-name <name> SPNEGO proxy service name
     --proxy-ssl-allow-beast Allow security flaw for interop for HTTPS proxy
     --proxy-tls13-ciphers <list> TLS 1.3 ciphersuites for proxy (OpenSSL)
     --proxy-tlsauthtype <type> TLS authentication type for HTTPS proxy
     --proxy-tlspassword <string> TLS password for HTTPS proxy
     --proxy-tlsuser <name> TLS username for HTTPS proxy
     --proxy-tlsv1   Use TLSv1 for HTTPS proxy
 -U, --proxy-user <user:password> Proxy user and password
     --proxy1.0 <host[:port]> Use HTTP/1.0 proxy on given port
 -p, --proxytunnel   Operate through an HTTP proxy tunnel (using CONNECT)
     --pubkey <key>  SSH Public key file name
 -Q, --quote         Send command(s) to server before transfer
     --random-file <file> File for reading random data from
 -r, --range <range> Retrieve only the bytes within RANGE
     --raw           Do HTTP "raw"; no transfer decoding
 -e, --referer <URL> Referrer URL
 -J, --remote-header-name Use the header-provided filename
 -O, --remote-name   Write output to a file named as the remote file
     --remote-name-all Use the remote file name for all URLs
 -R, --remote-time   Set the remote file's time on the local output
 -X, --request <command> Specify request command to use
     --request-target Specify the target for this request
     --resolve <host:port:address[,address]...> Resolve the host+port to this address
     --retry <num>   Retry request if transient problems occur
     --retry-connrefused Retry on connection refused (use with --retry)
     --retry-delay <seconds> Wait time between retries
     --retry-max-time <seconds> Retry only within this period
     --sasl-authzid <identity>  Use this identity to act as during SASL PLAIN authentication
     --sasl-ir       Enable initial response in SASL authentication
     --service-name <name> SPNEGO service name
 -S, --show-error    Show error even when -s is used
 -s, --silent        Silent mode
     --socks4 <host[:port]> SOCKS4 proxy on given host + port
     --socks4a <host[:port]> SOCKS4a proxy on given host + port
     --socks5 <host[:port]> SOCKS5 proxy on given host + port
     --socks5-basic  Enable username/password auth for SOCKS5 proxies
     --socks5-gssapi Enable GSS-API auth for SOCKS5 proxies
     --socks5-gssapi-nec Compatibility with NEC SOCKS5 server
     --socks5-gssapi-service <name> SOCKS5 proxy service name for GSS-API
     --socks5-hostname <host[:port]> SOCKS5 proxy, pass host name to proxy
 -Y, --speed-limit <speed> Stop transfers slower than this
 -y, --speed-time <seconds> Trigger 'speed-limit' abort after this time
     --ssl           Try SSL/TLS
     --ssl-allow-beast Allow security flaw to improve interop
     --ssl-no-revoke Disable cert revocation checks (Schannel)
     --ssl-revoke-best-effort Ignore revocation offline or missing revocation list errors (Schannel)
     --ssl-reqd      Require SSL/TLS
 -2, --sslv2         Use SSLv2
 -3, --sslv3         Use SSLv3
     --stderr        Where to redirect stderr
     --styled-output Enable styled output for HTTP headers
     --suppress-connect-headers Suppress proxy CONNECT response headers
     --tcp-fastopen  Use TCP Fast Open
     --tcp-nodelay   Use the TCP_NODELAY option
 -t, --telnet-option <opt=val> Set telnet option
     --tftp-blksize <value> Set TFTP BLKSIZE option
     --tftp-no-options Do not send any TFTP options
 -z, --time-cond <time> Transfer based on a time condition
     --tls-max <VERSION> Set maximum allowed TLS version
     --tls13-ciphers <list> TLS 1.3 ciphersuites (OpenSSL)
     --tlsauthtype <type> TLS authentication type
     --tlspassword   TLS password
     --tlsuser <name> TLS user name
 -1, --tlsv1         Use TLSv1.0 or greater
     --tlsv1.0       Use TLSv1.0 or greater
     --tlsv1.1       Use TLSv1.1 or greater
     --tlsv1.2       Use TLSv1.2 or greater
     --tlsv1.3       Use TLSv1.3 or greater
     --tr-encoding   Request compressed transfer encoding
     --trace <file>  Write a debug trace to FILE
     --trace-ascii <file> Like --trace, but without hex output
     --trace-time    Add time stamps to trace/verbose output
     --unix-socket <path> Connect through this Unix domain socket
 -T, --upload-file <file> Transfer local FILE to destination
     --url <url>     URL to work with
 -B, --use-ascii     Use ASCII/text transfer
 -u, --user <user:password> Server user and password
 -A, --user-agent <name> Send User-Agent <name> to server
 -v, --verbose       Make the operation more talkative
 -V, --version       Show version number and quit
 -w, --write-out <format> Use output FORMAT after completion
     --xattr         Store metadata in extended file attributes''')
print(command, ": not found")