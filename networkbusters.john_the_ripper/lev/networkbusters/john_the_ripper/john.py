"""
John the Ripper
Run John the Ripper on a password hash.
Homepage: -
GitHub: -
Type: IMAGE-BASED
Version: v1.0.0
"""

import levrt
from levrt import Cr, ctx, remote, annot
from levrt.annot.cats import Attck, BlackArch


@annot.meta(
    desc="Incremental: john --incremental <file hash>",
    params=[annot.Param("password_hash", "Password Hash"),
            annot.Param("timeout", "Timeout")],
    cats=[Attck.PrivilegeEscalation],
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
         # imports and Logging Setup
        import sys, subprocess, logging, os, json

        logging.basicConfig()
        logger = logging.getLogger("lev")
        logger.setLevel(logging.DEBUG)

        # Write Hash to File
        #logger.debug(hash)
        john_hash_file = "/john_hash_to_crack.txt"
        with open(john_hash_file, 'w') as f:
            f.write(password_hash)    
        
        # Run John the Ripper to Crack Hash
        if timeout >= 0:
            timeout_str = str(timeout)
            commands = ['./john/run/john', '--incremental', "--max-run-time=" + timeout_str, john_hash_file]
        else:
            commands = ['./john/run/john', '--incremental', john_hash_file]
        
        subprocess.run(commands)

        # Show Password Hashes to compare to passwords later: (not currently used, but may be necessary in the future)
        ciphertext_key_file = "cifertext_key"
        show_commands = ['/john/run/john', '--show=formats', john_hash_file]
        with open(ciphertext_key_file, 'w') as g:
            subprocess.run(show_commands, stdout=g)
        
        with open(ciphertext_key_file, 'r') as g:
            ciphertext_data = json.loads(g.read())
            
        ciphertext = ciphertext_data[0]["ciphertext"]

        # Load Cracked Password from File
        with open("/john/run/john.pot", 'r') as g:
            cracked_passwords = g.readlines()
            cracked_passwords = [line.rstrip() for line in cracked_passwords]
        
        password_to_hashes = {}
        
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
    cats=[Attck.PrivilegeEscalation],
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
         # imports and Logging Setup
        import sys, subprocess, logging, os, json

        logging.basicConfig()
        logger = logging.getLogger("lev")
        logger.setLevel(logging.DEBUG)

        # Write Hash to File
        #logger.debug(hash)
        john_hash_file = "/john_hash_to_crack.txt"
        with open(john_hash_file, 'w') as f:
            f.write(password_hash)    
        
        # Run John the Ripper to Crack Hash
        if timeout >= 0:
            timeout_str = str(timeout)
            commands = ['./john/run/john', '--incremental', "--max-run-time=" + timeout_str, john_hash_file]
        else:
            commands = ['./john/run/john', '--incremental', john_hash_file]
        
        subprocess.run(commands)

        # Show Password Hashes to compare to passwords later: (not currently used, but may be necessary in the future)
        ciphertext_key_file = "cifertext_key"
        show_commands = ['/john/run/john', '--show=formats', john_hash_file]
        with open(ciphertext_key_file, 'w') as g:
            subprocess.run(show_commands, stdout=g)
        
        with open(ciphertext_key_file, 'r') as g:
            ciphertext_data = json.loads(g.read())
            
        ciphertext = ciphertext_data[0]["ciphertext"]

        # Load Cracked Password from File
        with open("/john/run/john.pot", 'r') as g:
            cracked_passwords = g.readlines()
            cracked_passwords = [line.rstrip() for line in cracked_passwords]
        
        password_to_hashes = {}
        
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
            annot.Param("wordlist", "Wordlist"),
            annot.Param("rules", "Should Word Mangling Rules be Used?"),
            annot.Param("timeout", "Timeout")],
    cats=[Attck.PrivilegeEscalation],
)
def Wordlist(password_hash: str = "", wordlist: str = "", rules: bool = True, timeout: int = 10) -> Cr:
    """
    Run John the Ripper on a password hash with a wordlist 
    ```
    await Wordlist()
    ```
    """
    @levrt.remote
    def entry():
         # imports and Logging Setup
        import sys, subprocess, logging, os, json

        logging.basicConfig()
        logger = logging.getLogger("lev")
        logger.setLevel(logging.DEBUG)

        # Write Hash to File
        #logger.debug(hash)
        john_hash_file = "/john_hash_to_crack.txt"
        with open(john_hash_file, 'w') as f:
            f.write(password_hash)    
        
        # Run John the Ripper to Crack Hash
        if timeout >= 0:
            timeout_str = str(timeout)
            commands = ['./john/run/john', '--incremental', "--max-run-time=" + timeout_str, john_hash_file]
        else:
            commands = ['./john/run/john', '--incremental', john_hash_file]
        
        subprocess.run(commands)

        # Show Password Hashes to compare to passwords later: (not currently used, but may be necessary in the future)
        ciphertext_key_file = "cifertext_key"
        show_commands = ['/john/run/john', '--show=formats', john_hash_file]
        with open(ciphertext_key_file, 'w') as g:
            subprocess.run(show_commands, stdout=g)
        
        with open(ciphertext_key_file, 'r') as g:
            ciphertext_data = json.loads(g.read())
            
        ciphertext = ciphertext_data[0]["ciphertext"]

        # Load Cracked Password from File
        with open("/john/run/john.pot", 'r') as g:
            cracked_passwords = g.readlines()
            cracked_passwords = [line.rstrip() for line in cracked_passwords]
        
        password_to_hashes = {}
        
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
            annot.Param("timeout", "Timeout")],
    cats=[Attck.PrivilegeEscalation],
)
def Raw(password_hash: str = "", options: str = "", timeout: int = 10) -> Cr:
    """
    Run John the Ripper on a password hash with input options.
    ```
    await Raw()
    ```
    """
    @levrt.remote
    def entry():
         # imports and Logging Setup
        import sys, subprocess, logging, os, json

        logging.basicConfig()
        logger = logging.getLogger("lev")
        logger.setLevel(logging.DEBUG)

        # Write Hash to File
        #logger.debug(hash)
        john_hash_file = "/john_hash_to_crack.txt"
        with open(john_hash_file, 'w') as f:
            f.write(password_hash)    
        
        # Run John the Ripper to Crack Hash
        if timeout >= 0:
            timeout_str = str(timeout)
            commands = ['./john/run/john', '--incremental', "--max-run-time=" + timeout_str, john_hash_file]
        else:
            commands = ['./john/run/john', '--incremental', john_hash_file]
        
        subprocess.run(commands)

        # Show Password Hashes to compare to passwords later: (not currently used, but may be necessary in the future)
        ciphertext_key_file = "cifertext_key"
        show_commands = ['/john/run/john', '--show=formats', john_hash_file]
        with open(ciphertext_key_file, 'w') as g:
            subprocess.run(show_commands, stdout=g)
        
        with open(ciphertext_key_file, 'r') as g:
            ciphertext_data = json.loads(g.read())
            
        ciphertext = ciphertext_data[0]["ciphertext"]

        # Load Cracked Password from File
        with open("/john/run/john.pot", 'r') as g:
            cracked_passwords = g.readlines()
            cracked_passwords = [line.rstrip() for line in cracked_passwords]
        
        password_to_hashes = {}
        
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









__lev__ = annot.meta([Incremental, Single, Wordlist, Raw],
                     desc = "John the Ripper Password Cracker", # name of tool
                     cats = {
                        Attck: [Attck.PrivilegeEscalation] # ATT&CK
                     })