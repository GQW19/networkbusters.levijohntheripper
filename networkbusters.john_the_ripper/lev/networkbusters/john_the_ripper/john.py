"""
John the Ripper
Run John the Ripper on a password hash.
Homepage: -
GitHub: -
Type: IMAGE-BASED
Version: v1.0.0
"""

import levrt
from levrt import Cr, ctx, remote, annot, File
from levrt.annot.cats import Attck, BlackArch


@annot.meta(
    desc="Base: john <file hash>",
    params=[annot.Param("password_hash", "Password Hash"),
            annot.Param("wordlist", "Wordlist in valid json (set to 'default' to use default built in wordlist)"),
            annot.Param("timeout", "Timeout")],
    cats=[Attck.PrivilegeEscalation, Attck.CredentialAccess, Attck.LateralMovement],
)
def Base(password_hash: str = "", wordlist: str = "[]", timeout: int = 10) -> Cr:
    """
    Run John the Ripper on a password hash in single, then wordlist, then incremental mode with a timeout.
    ```
    await Base()
    ```
    """
    @levrt.remote
    def entry():
        ## Imports and Logging Setup
        import sys, subprocess, logging, os, json
        logging.basicConfig()
        logger = logging.getLogger("lev")
        logger.setLevel(logging.DEBUG)


        ## Write Hash to File
        john_hash_file = "/john_hash_to_crack.txt"
        with open(john_hash_file, 'w') as f:
            f.write(password_hash)    


        ## Create Wordlist
        if wordlist != "default":
            used_wordlist = json.loads(wordlist)
            wordlist_file = "/john/run/password.lst"
            with open(wordlist_file, 'w') as f:
                f.write('\n'.join(used_wordlist))
        

        ## Create Commands for John
        if timeout >= 0:
            timeout_str = str(timeout)
            commands = ['./john/run/john', "--max-run-time=" + timeout_str, john_hash_file]
        else:
            commands = ['./john/run/john', john_hash_file]  
        

        ## Run John the Ripper
        subprocess.run(commands)


        ## Optionally: Show Password Hashes to compare to passwords later: (not currently used, but may be necessary in the future)
        # ciphertext_key_file = "cifertext_key"
        # show_commands = ['/john/run/john', '--show=formats', john_hash_file]
        # with open(ciphertext_key_file, 'w') as g:
        #     subprocess.run(show_commands, stdout=g)
        # with open(ciphertext_key_file, 'r') as g:
        #     ciphertext_data = json.loads(g.read())
        # ciphertext = ciphertext_data[0]["ciphertext"]


        ## Load Cracked Password from File
        with open("/john/run/john.pot", 'r') as g:
            cracked_passwords = g.readlines()
            cracked_passwords = [line.rstrip() for line in cracked_passwords]
        
        password_to_hashes = {}
        

        ## Set Cracked Password in response
        #for c in cracked_passwords:
        if len(cracked_passwords) > 0:
            c = cracked_passwords[0]
            passwords = c.split(':', 1)
            hash = passwords[0]
            password = passwords[1]
            password_to_hashes[hash] = password
            logger.debug(password)
            ctx.set(msg="Password Successfully Cracked")
            ctx.set(password=f"{password}")
        else:
            ctx.set(msg="Password Not Cracked Successfully")
            ctx.set(password='')


    return Cr("2746dc3d57b0", entry=entry())





@annot.meta(
    desc="Incremental: john --incremental <file hash>",
    params=[annot.Param("password_hash", "Password Hash"),
            annot.Param("timeout", "Timeout")],
    cats=[Attck.PrivilegeEscalation, Attck.CredentialAccess, Attck.LateralMovement],
)
def Incremental(password_hash: str = "", timeout: int = 10) -> Cr:
    """
    Run John the Ripper on a password hash in incremental mode. 
    ```
    await Incremental()
    ```
    """
    @levrt.remote
    def entry():
        ## Imports and Logging Setup
        import sys, subprocess, logging, os, json
        logging.basicConfig()
        logger = logging.getLogger("lev")
        logger.setLevel(logging.DEBUG)


        ## Write Hash to File
        john_hash_file = "/john_hash_to_crack.txt"
        with open(john_hash_file, 'w') as f:
            f.write(password_hash)    
        

        ## Create Commands for John
        if timeout >= 0:
            timeout_str = str(timeout)
            commands = ['./john/run/john', '--incremental', "--max-run-time=" + timeout_str, john_hash_file]
        else:
            commands = ['./john/run/john', '--incremental', john_hash_file]
        

        ## Run John the Ripper
        subprocess.run(commands)


        ## Optionally: Show Password Hashes to compare to passwords later: (not currently used, but may be necessary in the future)
        # ciphertext_key_file = "cifertext_key"
        # show_commands = ['/john/run/john', '--show=formats', john_hash_file]
        # with open(ciphertext_key_file, 'w') as g:
        #     subprocess.run(show_commands, stdout=g)
        # with open(ciphertext_key_file, 'r') as g:
        #     ciphertext_data = json.loads(g.read())
        # ciphertext = ciphertext_data[0]["ciphertext"]


        ## Load Cracked Password from File
        with open("/john/run/john.pot", 'r') as g:
            cracked_passwords = g.readlines()
            cracked_passwords = [line.rstrip() for line in cracked_passwords]
        
        password_to_hashes = {}
        
        ## Set Cracked Password in response
        #for c in cracked_passwords:
        if len(cracked_passwords) > 0:
            c = cracked_passwords[0]
            passwords = c.split(':', 1)
            hash = passwords[0]
            password = passwords[1]
            password_to_hashes[hash] = password
            ctx.set(msg="Password Successfully Cracked")
            ctx.set(password=f"{password}")
        else:
            ctx.set(msg="Password Not Cracked Successfully")
            ctx.set(password='')


    return Cr("2746dc3d57b0", entry=entry())


@annot.meta(
    desc="Single: john --single <file hash>",
    params=[annot.Param("password_hash", "Password Hash"),
            annot.Param("timeout", "Timeout")],
    cats=[Attck.PrivilegeEscalation, Attck.CredentialAccess, Attck.LateralMovement],
)
def Single(password_hash: str = "", timeout: int = 10) -> Cr:
    """
    Run John the Ripper on a password hash in single mode. 
    ```
    await Single()
    ```
    """
    @levrt.remote
    def entry():
        ## Imports and Logging Setup
        import sys, subprocess, logging, os, json
        logging.basicConfig()
        logger = logging.getLogger("lev")
        logger.setLevel(logging.DEBUG)


        ## Write Hash to File
        john_hash_file = "/john_hash_to_crack.txt"
        with open(john_hash_file, 'w') as f:
            f.write(password_hash)    
        

        ## Create Commands for John
        if timeout >= 0:
            timeout_str = str(timeout)
            commands = ['./john/run/john', '--single', "--max-run-time=" + timeout_str, john_hash_file]
        else:
            commands = ['./john/run/john', '--single', john_hash_file]
        

        ## Run John the Ripper
        subprocess.run(commands)


        ## Optionally: Show Password Hashes to compare to passwords later: (not currently used, but may be necessary in the future)
        # ciphertext_key_file = "cifertext_key"
        # show_commands = ['/john/run/john', '--show=formats', john_hash_file]
        # with open(ciphertext_key_file, 'w') as g:
        #     subprocess.run(show_commands, stdout=g)
        # with open(ciphertext_key_file, 'r') as g:
        #     ciphertext_data = json.loads(g.read())
        # ciphertext = ciphertext_data[0]["ciphertext"]


        ## Load Cracked Password from File
        with open("/john/run/john.pot", 'r') as g:
            cracked_passwords = g.readlines()
            cracked_passwords = [line.rstrip() for line in cracked_passwords]
        
        password_to_hashes = {}
        

        ## Set Cracked Password in response
        #for c in cracked_passwords:
        if len(cracked_passwords) > 0:
            c = cracked_passwords[0]
            passwords = c.split(':', 1)
            hash = passwords[0]
            password = passwords[1]
            password_to_hashes[hash] = password
            ctx.set(msg="Password Successfully Cracked")
            ctx.set(password=f"{password}")
        else:
            ctx.set(msg="Password Not Cracked Successfully")
            ctx.set(password='')


    return Cr("2746dc3d57b0", entry=entry())



@annot.meta(
    desc="Wordlist: john --wordlist=<wordlist file> --rules <file hash>",
    params=[annot.Param("password_hash", "Password Hash"),
            annot.Param("wordlist", "Wordlist in valid json"),
            annot.Param("rules", "Should Word Mangling Rules be Used?"),
            annot.Param("timeout", "Timeout")],
    cats=[Attck.PrivilegeEscalation, Attck.CredentialAccess, Attck.LateralMovement],
)
def Wordlist(password_hash: str = "", wordlist: str = "[]", rules: bool = True, timeout: int = 10) -> Cr:
    """
    Run John the Ripper on a password hash with a wordlist 
    ```
    await Wordlist()
    ```
    """
    @levrt.remote
    def entry():
        ## Imports and Logging Setup
        import sys, subprocess, logging, os, json
        logging.basicConfig()
        logger = logging.getLogger("lev")
        logger.setLevel(logging.DEBUG)


        ## Write Hash to File
        john_hash_file = "/john_hash_to_crack.txt"
        with open(john_hash_file, 'w') as f:
            f.write(password_hash)    
        

        # Create Wordlist:
        #wordlist = ['123'] # ['hellot0_you', 'hello2', 'hello3']
        if wordlist != "default":
            used_wordlist = json.loads(wordlist)
            logger.debug(used_wordlist)
            wordlist_file = "/wordlist_file"
            with open(wordlist_file, 'w') as f:
                f.write('\n'.join(used_wordlist))
        else:
            wordlist_file = "/john/run/password.lst"
            
        
        ## Create Commands for John
        commands = ['./john/run/john', '--wordlist='+wordlist_file]
        if rules == True:
            commands += ['--rules']
        
        if timeout >= 0:
            timeout_str = str(timeout)
            commands += ["--max-run-time=" + timeout_str, john_hash_file]
        else:
            commands += [john_hash_file]
        

        ## Run John the Ripper
        subprocess.run(commands)


        ## Optionally: Show Password Hashes to compare to passwords later: (not currently used, but may be necessary in the future)
        # ciphertext_key_file = "cifertext_key"
        # show_commands = ['/john/run/john', '--show=formats', john_hash_file]
        # with open(ciphertext_key_file, 'w') as g:
        #     subprocess.run(show_commands, stdout=g)
        # with open(ciphertext_key_file, 'r') as g:
        #     ciphertext_data = json.loads(g.read())
        # ciphertext = ciphertext_data[0]["ciphertext"]


        ## Load Cracked Password from File
        with open("/john/run/john.pot", 'r') as g:
            cracked_passwords = g.readlines()
            cracked_passwords = [line.rstrip() for line in cracked_passwords]
        
        password_to_hashes = {}
        

        ## Set Cracked Password in response
        #for c in cracked_passwords:
        if len(cracked_passwords) > 0:
            c = cracked_passwords[0]
            passwords = c.split(':', 1)
            hash = passwords[0]
            password = passwords[1]
            password_to_hashes[hash] = password
            ctx.set(msg="Password Successfully Cracked")
            ctx.set(password=f"{password}")
        else:
            ctx.set(msg="Password Not Cracked Successfully")
            ctx.set(password='')


    return Cr("2746dc3d57b0", entry=entry())



@annot.meta(
    desc="Raw: john <raw options> <file hash>",
    params=[annot.Param("password_hash", "Password Hash"),
            annot.Param("options", "Command Flags"),
            annot.Param("wordlist", "Wordlist"),
            annot.Param("timeout", "Timeout")],
    cats=[Attck.PrivilegeEscalation, Attck.CredentialAccess, Attck.LateralMovement],
)
def Raw(password_hash: str = "", wordlist: str = "default", options: str = " ", timeout: int = 10) -> Cr:
    """
    Run John the Ripper on a password hash with input options.
    ```
    await Raw()
    ```
    """
    @levrt.remote
    def entry():
        ## Imports and Logging Setup
        import sys, subprocess, logging, os, json
        logging.basicConfig()
        logger = logging.getLogger("lev")
        logger.setLevel(logging.DEBUG)


        ## Write Hash to File
        john_hash_file = "/john_hash_to_crack.txt"
        with open(john_hash_file, 'w') as f:
            f.write(password_hash)    
        

        ## Create Wordlist:
        if wordlist != "default":
            used_wordlist = json.loads(wordlist)
            logger.debug(used_wordlist)
            wordlist_file = "/john/run/password.lst"
            with open(wordlist_file, 'w') as f:
                f.write('\n'.join(used_wordlist))


        ## Create Commands for John
        if timeout >= 0:
            timeout_str = str(timeout)
            commands1 = ['./john/run/john']
            commands2 = ["--max-run-time=" + timeout_str, john_hash_file]
        else:
            commands1 = ['./john/run/john'] 
            commands2 = [john_hash_file]


        ## Load Input Commands
        option_commands = options.split(" ")       
        commands = commands1 + option_commands + commands2
        

        ## Run John the Ripper
        subprocess.run(commands)


        ## Optionally: Show Password Hashes to compare to passwords later: (not currently used, but may be necessary in the future)
        # ciphertext_key_file = "cifertext_key"
        # show_commands = ['/john/run/john', '--show=formats', john_hash_file]
        # with open(ciphertext_key_file, 'w') as g:
        #     subprocess.run(show_commands, stdout=g)
        # with open(ciphertext_key_file, 'r') as g:
        #     ciphertext_data = json.loads(g.read())
        # ciphertext = ciphertext_data[0]["ciphertext"]


        ## Load Cracked Password from File
        with open("/john/run/john.pot", 'r') as g:
            cracked_passwords = g.readlines()
            cracked_passwords = [line.rstrip() for line in cracked_passwords]

        password_to_hashes = {}
        

        ## Set Cracked Password in response
        #for c in cracked_passwords:
        if len(cracked_passwords) > 0:
            c = cracked_passwords[0]
            passwords = c.split(':', 1)
            hash = passwords[0]
            password = passwords[1]
            password_to_hashes[hash] = password
            ctx.set(msg="Password Successfully Cracked")
            ctx.set(password=f"{password}")
        else:
            ctx.set(msg="Password Not Cracked Successfully")
            ctx.set(password='')


    return Cr("2746dc3d57b0", entry=entry())




@annot.meta(
    desc="Hash Extractor: <file_type>2john input_file > output_file",
    params=[annot.Param("file_to_extract", "File to Extract Password Hashes From"),
            annot.Param("dmg2john", "dmg2john"),
            annot.Param("racf2john", "racf2john"),
            annot.Param("wpapcap2john", "wpapcap2john"),
            annot.Param("keepass2john", "keepass2john"),
            annot.Param("rar2john", "rar2john"),
            annot.Param("zip2john", "zip2john"),
            annot.Param("gpg2john", "gpg2john"),
            annot.Param("hccap2john", "hccap2john"),
            annot.Param("putty2john", "putty2john"),
            annot.Param("uaf2john", "uaf2john"),
            annot.Param("vncpcap2john", "vncpcap2john"),
            annot.Param("other", "other"),
            annot.Param("hash_extractor", "(If Other) Name Of Hash Extractor Tool")],
    cats=[Attck.PrivilegeEscalation, Attck.CredentialAccess, Attck.LateralMovement],
)
def extract_hash(file_to_extract: File = None, 
                dmg2john: bool = False,
                racf2john: bool = False,
                wpapcap2john: bool = False,
                keepass2john: bool = False,
                rar2john: bool = False,
                zip2john: bool = True,
                gpg2john: bool = False,
                hccap2john: bool = False,
                putty2john: bool = False,
                uaf2john: bool = False,
                vncpcap2john: bool = False,
                other: bool = False,
                hash_extractor: str="") -> Cr:
    """
    Extract Hash from Encrypted File
    ```
    await extract_hash()
    ```
    """
    @levrt.remote
    def entry():
        ## Imports and Logging Setup
        import sys, subprocess, logging, os, json
        logging.basicConfig()
        logger = logging.getLogger("lev")
        logger.setLevel(logging.DEBUG)


        ## Choose Extraction Type:
        extractor = None
        if dmg2john == True:
            extractor = ["./john/run/dmg2john"]
        elif racf2john == True:
            extractor = ["./john/run/racf2john"]
        elif wpapcap2john == True:
            extractor = ["./john/run/wpapcap2john"]
        elif keepass2john == True:
            extractor = ["./john/run/keepass2john"]
        elif rar2john == True:
            extractor = ["./john/run/rar2john"]
        elif zip2john == True:
            extractor = ["./john/run/zip2john"]
        elif gpg2john == True:
            extractor = ["./john/run/gpg2john"]
        elif hccap2john == True:
            extractor = ["./john/run/hccap2john"]
        elif putty2john == True:
            extractor = ["./john/run/putty2john"]
        elif uaf2john == True:
            extractor = ["./john/run/uaf2john"]
        elif vncpcap2john == True:
            extractor = ["./john/run/vncpcap2john"]
        elif other:
            extractor = [hash_extractor.split(' ')]
            # Set Correct Filepath to tool????
            extractor[0] = './john/run/' + extractor[0]


        ## Create Command and Run Extraction
        loaded_filepath = "/file_to_extract"  
        hash_file = "output"
        with open(hash_file, 'w') as hash_file_opened:
            if extractor is None or len(extractor) == 0:
                # If no hash extractor porvided.
                with open(loaded_filepath, 'r') as g:
                    for line in g:
                        hash_file_opened.write(line)
            else:
                # Else run the hash extractor
                commands = extractor + [loaded_filepath]      
                subprocess.run(commands, stdout=hash_file_opened)
            

        ## Check If Extraction Worked and Set Response
        size = os.path.getsize(hash_file)
        if size > 0:
            with open(hash_file, 'r') as g:
                hash_data = g.read()
            ctx.set(success=True)
            ctx.set(hash=hash_data)
        else:
            ctx.set(success=False)
            ctx.set(hash='')

    return Cr("2746dc3d57b0", entry=entry(), files={"/file_to_extract": file_to_extract})





__lev__ = annot.meta([Incremental, Single, Wordlist, Raw, extract_hash],
                     desc = "John the Ripper Password Cracker", # name of tool
                     cats = {
                        Attck: [Attck.PrivilegeEscalation, Attck.CredentialAccess, Attck.LateralMovement] # ATT&CK
                     })