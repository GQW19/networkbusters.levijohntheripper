"""
CeWL + CUPP + John the Ripper Workflows. 
Run a full password cracking suite on an encrypted file. 
Homepage: -
GitHub: https://github.com/GQW19/networkbusters.levijohntheripper
Type: IMAGE-BASED
Version: v0.1.29
"""

from levrt import ctx, annot, Concurrent, File
from . import john
from lev.aorona.cewlcupp.cewlcupp import CewlCupp, Cupp_User_Profile

@annot.meta(
    desc = "Run John the Ripper on Encrytped File",
    params = [annot.Param("file_to_extract", "File to Extract Password Hashes From"),
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
            annot.Param("hash_extractor", "(If Other) Name Of Hash Extractor Tool"), 
            annot.Param("wordlist", "John: Wordlist in valid json"),
            annot.Param("timeout", "John: Timeout")],
            
)
async def JTR_Base_Workflow(file_to_extract: File, 
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
                hash_extractor: str="", 
                wordlist: str = "default",
                timeout: int = 10):
    """
    Lev Password Cracker Series:

    Our Password Cracking workflows take input from CeWL and CUPP generated wordlists and use them in John the Ripper to crack the password hashes of encrypted files. 

    John the Ripper Base Workflow: Run John the Ripper on an encrypted file's hash with only the default John wordlist of common passwords.  
    ```
    await JTR_Base_Workflow(..)
    ```
    """

    import logging
    logging.basicConfig()
    logger = logging.getLogger("lev")
    logger.setLevel(logging.DEBUG)
    logger.debug("[lev app - password cracker] log from asset - start point")

    # EXTRACT HASH FROM FILE
    doc = await john.extract_hash(file_to_extract=file_to_extract, 
                dmg2john=dmg2john,
                racf2john = racf2john,
                wpapcap2john=wpapcap2john,
                keepass2john=keepass2john,
                rar2john=rar2john,
                zip2john=zip2john,
                gpg2john=gpg2john,
                hccap2john=hccap2john,
                putty2john=putty2john,
                uaf2john=uaf2john,
                vncpcap2john=vncpcap2john,
                other=other,
                hash_extractor=hash_extractor)
    data = await doc.get()
    logger.debug(f"[lev app - password hash extraction {data['hash']}")

    hash_value = data["hash"]
    print(hash_value)


    # RUN JOHN THE RIPPER
    if data["success"] == True:
        doc = await john.Base(hash_value, wordlist, timeout)
        data = await doc.get()
        logger.debug("Password:")
        logger.debug(data['password'])



@annot.meta(
    desc = "CeWL Wordlist Workflow",
    params = [annot.Param("file_to_extract", "Encrypted File"),
            annot.Param("dmg2john", "Hash Extractor: Use dmg2john"),
            annot.Param("racf2john", "Hash Extractor: Use racf2john"),
            annot.Param("wpapcap2john", "Hash Extractor: Use wpapcap2john"),
            annot.Param("keepass2john", "Hash Extractor: Use keepass2john"),
            annot.Param("rar2john", "Hash Extractor: Use rar2john"),
            annot.Param("zip2john", "Hash Extractor: Use zip2john"),
            annot.Param("gpg2john", "Hash Extractor: Use gpg2john"),
            annot.Param("hccap2john", "Hash Extractor: Use hccap2john"),
            annot.Param("putty2john", "Hash Extractor: Use putty2john"),
            annot.Param("uaf2john", "Hash Extractor: Use uaf2john"),
            annot.Param("vncpcap2john", "Hash Extractor: Use vncpcap2john"),
            annot.Param("other", "Hash Extractor: Use other"),
            annot.Param("hash_extractor", "Hash Extractor: (If Other) Name Of Hash Extractor Tool"), 
            annot.Param("timeout", "John: Timeout"), 
            annot.Param("depth", "Cewl: depth to spider"),
            annot.Param("min_length", "CeWL: Minimum Word Length"),
            annot.Param("offsite", "CeWL: Allow Spider to visit other sites"),
            annot.Param("url", "CeWL: URL to spider"),
            annot.Param("concatenate_cewl", "CeWL-CuPP: Concatenate all words from wordlist"),
            annot.Param("special_chars_cewl", "CeWL-CuPP: Add special chars at the end of words"),
            annot.Param("random_nums_cewl", "CeWL-CuPP: some random numbers at the end of words"),
            annot.Param("leet_prof_cewl", "CeWL-CuPP: Leet mode")]
)
async def JTR_CeWL_Wordlist_Workflow(file_to_extract: File, 
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
                hash_extractor: str="", 
                timeout: int = 10, 
                url: str =  '',
                depth: int = 1,
                min_length: int = 3,
                offsite: bool = False, 
                concatenate_cewl: bool = False,
                special_chars_cewl: bool = False,
                random_nums_cewl: bool = False,
                leet_cewl: bool = False):
    """
    Lev Password Cracker Series:

    Our Password Cracking workflows take input from CeWL and CUPP generated wordlists and use them in John the Ripper to crack the password hashes of encrypted files. 

    CeWL Wordlist Workflow: Run CeWL on URL, pass resulting wordlist to CuPP, then pass wordlist to John the ripper to crack an encrypted file. 
    ```
    await JTR_CeWL_Wordlist_Workflow(..)
    ```
    (Due to image uploading technical difficulties, this workflow will use the default John Wordlist and bypass CeWL and CUPP until the cause of the cewlcupp image issue is found and resolved).
    """

    import logging
    logging.basicConfig()
    logger = logging.getLogger("lev")
    logger.setLevel(logging.DEBUG)
    logger.debug("[lev app - password cracker] log from asset - start point")

    # EXTRACT HASH FROM FILE
    doc = await john.extract_hash(file_to_extract=file_to_extract, 
                dmg2john=dmg2john,
                racf2john = racf2john,
                wpapcap2john=wpapcap2john,
                keepass2john=keepass2john,
                rar2john=rar2john,
                zip2john=zip2john,
                gpg2john=gpg2john,
                hccap2john=hccap2john,
                putty2john=putty2john,
                uaf2john=uaf2john,
                vncpcap2john=vncpcap2john,
                other=other,
                hash_extractor=hash_extractor)
    data = await doc.get()
    logger.debug(f"[lev app - password hash extraction {data['hash']}")

    hash_value = data["hash"]
    print(hash_value)


    # GET CEWL/CUPP WORDLIST
    try:
        doc = await CewlCupp(url=url,
                    depth=depth,
                    min_length=min_length,
                    offsite=offsite, 
                    concatenate_cewl = concatenate_cewl,
                    special_chars_cewl = special_chars_cewl,
                    random_nums_cewl = random_nums_cewl,
                    leet_cewl = leet_cewl)
        data = await doc.get()
        wordlist = data["wordlist"]
    except Exception:
        wordlist = '["Hello2_y0u", "a1b2c3"]'


    # RUN JOHN THE RIPPER
    if data["success"] == True:
        doc = await john.Base(hash_value, wordlist, timeout)
        data = await doc.get()
        logger.debug("Password:")
        logger.debug(data['password'])



@annot.meta(
    desc = "CuPP Wordlist Workflow with User Profiling",
    params = [annot.Param("file_to_extract", "Encrypted File"),
            annot.Param("dmg2john", "Hash Extractor: Use dmg2john"),
            annot.Param("racf2john", "Hash Extractor: Use racf2john"),
            annot.Param("wpapcap2john", "Hash Extractor: Use wpapcap2john"),
            annot.Param("keepass2john", "Hash Extractor: Use keepass2john"),
            annot.Param("rar2john", "Hash Extractor: Use rar2john"),
            annot.Param("zip2john", "Hash Extractor: Use zip2john"),
            annot.Param("gpg2john", "Hash Extractor: Use gpg2john"),
            annot.Param("hccap2john", "Hash Extractor: Use hccap2john"),
            annot.Param("putty2john", "Hash Extractor: Use putty2john"),
            annot.Param("uaf2john", "Hash Extractor: Use uaf2john"),
            annot.Param("vncpcap2john", "Hash Extractor: Use vncpcap2john"),
            annot.Param("other", "Hash Extractor: Use other"),
            annot.Param("hash_extractor", "Hash Extractor: (If Other) Name Of Hash Extractor Tool"), 
            annot.Param("timeout", "John: Timeout"), 
            annot.Param("first_name", "CuPP Profiling: (Required, default='User') Password Creator's First Name"),
            annot.Param("surname", "CuPP Profiling: Password Creator's Surname"),
            annot.Param("nickname", "CuPP Profiling: Password Creator's Nickname"),
            annot.Param("birtday", "CuPP Profiling: (Required, default=00000000) Password Creator's Birthday (DDMMYYYY)"),
            annot.Param("partners_name", "CuPP Profiling: Password Creator's Partner's Name"),
            annot.Param("partners_nickname", "CuPP Profiling: Password Creator's Partner's Nickname"),
            annot.Param("partners_birthday", "CuPP Profiling: Password Creator's Partner's Birthday (DDMMYYYY)"),
            annot.Param("childs_name", "CuPP Profiling: Password Creator's Child's Name"),
            annot.Param("childs_nickname", "CuPP Profiling: Password Creator's Child's Nickname"),
            annot.Param("childs_birthday", "CuPP Profiling: Password Creator's Child's Birthday"),
            annot.Param("pets_name", "CuPP Profiling: Password Creator's Pet's Name"),
            annot.Param("company", "CuPP Profiling: Password Creator's Company"),
            annot.Param("keywords", "CuPP Profiling:Add words related to the Password Creator?"),
            annot.Param("related_words", "CuPP Profiling: Words related to the Password Creator"),
            annot.Param("special_chars_prof", "CuPP Profiling: Add special chars at the end of words"),
            annot.Param("random_nums_prof", "CuPP Profiling: some random numbers at the end of words"),
            annot.Param("leet_prof", "CuPP Profiling: Leet mode")]
)
async def JTR_CUPP_Wordlist_Workflow(file_to_extract: File, 
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
                hash_extractor: str="", 
                timeout: int = 10, 
                first_name: str = "User",
                surname: str = "",
                nickname: str = "",
                birthday: str="00000000",
                partners_name: str = "",
                partners_nickname: str = "",
                partners_birthday: str ="",
                childs_name: str = "",
                childs_nickname: str = "",
                childs_birthday: str = "", 
                pets_name: str = "",
                company: str = "",
                keywords: bool = False,
                related_words: str = "",
                special_chars_prof: bool = False,
                random_nums_prof: bool = False,
                leet_prof: bool = False):
    """
    Lev Password Cracker Series:

    Our Password Cracking workflows take input from CeWL and CUPP generated wordlists and use them in John the Ripper to crack the password hashes of encrypted files. 

    CUPP Wordlist Workflow: Create wordlist with input profiled user information, then pass the wordlist to John The Ripper to crack an encrypted file. 
    ```
    await JTR_CUPP_Wordlist_Workflow(..)
    ```
    Due to image uploading technical difficulties, this workflow will use the default John Wordlist and bypass CeWL and CUPP until the cause of the cewlcupp image issue is found and resolved).
    """

    import logging
    logging.basicConfig()
    logger = logging.getLogger("lev")
    logger.setLevel(logging.DEBUG)
    logger.debug("[lev app - password cracker] log from asset - start point")

    # EXTRACT HASH FROM FILE
    doc = await john.extract_hash(file_to_extract=file_to_extract, 
                dmg2john=dmg2john,
                racf2john = racf2john,
                wpapcap2john=wpapcap2john,
                keepass2john=keepass2john,
                rar2john=rar2john,
                zip2john=zip2john,
                gpg2john=gpg2john,
                hccap2john=hccap2john,
                putty2john=putty2john,
                uaf2john=uaf2john,
                vncpcap2john=vncpcap2john,
                other=other,
                hash_extractor=hash_extractor)
    data = await doc.get()
    logger.debug(f"[lev app - password hash extraction {data['hash']}")

    hash_value = data["hash"]
    print(hash_value)

    # GET CUPP -i WORDLIST:
    try:
        doc = await Cupp_User_Profile(first_name=first_name,
                                                surname=surname,
                                                nickname=nickname,
                                                birthday=birthday,
                                                partners_name=partners_name,
                                                partners_nickname=partners_nickname,
                                                partners_birthday=partners_birthday,
                                                childs_name=childs_name,
                                                childs_nickname=childs_nickname,
                                                childs_birthday = childs_birthday, 
                                                pets_name = pets_name,
                                                company=company,
                                                keywords=keywords,
                                                related_words=related_words,
                                                special_chars=special_chars_prof,
                                                random_nums=random_nums_prof,
                                                leet=leet_prof)
        data = await doc.get()
        wordlist = data["wordlist"]
    except Exception:
        wordlist = '["Hello2_y0u", "a1b2c3"]'

    # RUN JOHN THE RIPPER
    if data["success"] == True:
        doc = await john.Base(hash_value, wordlist, timeout)
        data = await doc.get()
        logger.debug("Password:")
        logger.debug(data['password'])




@annot.meta(
    desc = "Wordlist Workflow with User Profiling",
    params = [annot.Param("file_to_extract", "Encrypted File"),
            annot.Param("dmg2john", "Hash Extractor: Use dmg2john"),
            annot.Param("racf2john", "Hash Extractor: Use racf2john"),
            annot.Param("wpapcap2john", "Hash Extractor: Use wpapcap2john"),
            annot.Param("keepass2john", "Hash Extractor: Use keepass2john"),
            annot.Param("rar2john", "Hash Extractor: Use rar2john"),
            annot.Param("zip2john", "Hash Extractor: Use zip2john"),
            annot.Param("gpg2john", "Hash Extractor: Use gpg2john"),
            annot.Param("hccap2john", "Hash Extractor: Use hccap2john"),
            annot.Param("putty2john", "Hash Extractor: Use putty2john"),
            annot.Param("uaf2john", "Hash Extractor: Use uaf2john"),
            annot.Param("vncpcap2john", "Hash Extractor: Use vncpcap2john"),
            annot.Param("other", "Hash Extractor: Use other"),
            annot.Param("hash_extractor", "Hash Extractor: (If Other) Name Of Hash Extractor Tool"), 
            annot.Param("timeout", "John: Timeout"), 
            annot.Param("url", "CeWL: URL to spider"), 
            annot.Param("depth", "Cewl: depth to spider"),
            annot.Param("min_length", "CeWL: Minimum Word Length"),
            annot.Param("offsite", "CeWL: Allow Spider to visit other sites"),
            annot.Param("concatenate_cewl", "CeWL-CuPP: Concatenate all words from wordlist"),
            annot.Param("special_chars_cewl", "CeWL-CuPP: Add special chars at the end of words"),
            annot.Param("random_nums_cewl", "CeWL-CuPP: some random numbers at the end of words"),
            annot.Param("leet_prof_cewl", "CeWL-CuPP: Leet mode"),
            annot.Param("first_name", "CuPP Profiling: (Required, default='User') Password Creator's First Name"),
            annot.Param("surname", "CuPP Profiling: Password Creator's Surname"),
            annot.Param("nickname", "CuPP Profiling: Password Creator's Nickname"),
            annot.Param("birtday", "CuPP Profiling: (Required, default=00000000) Password Creator's Birthday (DDMMYYYY)"),
            annot.Param("partners_name", "CuPP Profiling: Password Creator's Partner's Name"),
            annot.Param("partners_nickname", "CuPP Profiling: Password Creator's Partner's Nickname"),
            annot.Param("partners_birthday", "CuPP Profiling: Password Creator's Partner's Birthday (DDMMYYYY)"),
            annot.Param("childs_name", "CuPP Profiling: Password Creator's Child's Name"),
            annot.Param("childs_nickname", "CuPP Profiling: Password Creator's Child's Nickname"),
            annot.Param("childs_birthday", "CuPP Profiling: Password Creator's Child's Birthday"),
            annot.Param("pets_name", "CuPP Profiling: Password Creator's Pet's Name"),
            annot.Param("company", "CuPP Profiling: Password Creator's Company"),
            annot.Param("keywords", "CuPP Profiling:Add words related to the Password Creator?"),
            annot.Param("related_words", "CuPP Profiling: Words related to the Password Creator"),
            annot.Param("special_chars_prof", "CuPP Profiling: Add special chars at the end of words"),
            annot.Param("random_nums_prof", "CuPP Profiling: some random numbers at the end of words"),
            annot.Param("leet_prof", "CuPP Profiling: Leet mode")]
)
async def JTR_CeWL_CUPP_Wordlist_Workflow(file_to_extract: File, 
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
                hash_extractor: str="", 
                timeout: int = 10, 
                url: str = '',
                depth: int = 1,
                min_length: int = 3,
                offsite: bool = False, 
                concatenate_cewl: bool = False,
                special_chars_cewl: bool = False,
                random_nums_cewl: bool = False,
                leet_cewl: bool = False,
                first_name: str = "User",
                surname: str = "",
                nickname: str = "",
                birthday: str="00000000",
                partners_name: str = "",
                partners_nickname: str = "",
                partners_birthday: str ="",
                childs_name: str = "",
                childs_nickname: str = "",
                childs_birthday: str = "", 
                pets_name: str = "",
                company: str = "",
                keywords: bool = False,
                related_words: str = "",
                special_chars_prof: bool = False,
                random_nums_prof: bool = False,
                leet_prof: bool = False):
    """
    Lev Password Cracker Series:

    Our Password Cracking workflows take input from CeWL and CUPP generated wordlists and use them in John the Ripper to crack the password hashes of encrypted files. 

    CeWL/CUPP Wordlist Workflow: Run CeWL on URL, pass resulting wordlist to CUPP, add to wordlist with input profiled user information, then pass wordlist to John The Ripper to crack an encrypted file. 
    ```
    await JTR_CeWL_CUPP_Wordlist_Workflow(..)
    ```
    (Due to image uploading technical difficulties, this workflow will use the default John Wordlist and bypass CeWL and CUPP until the cause of the cewlcupp image issue is found and resolved).
    """

    import logging
    logging.basicConfig()
    logger = logging.getLogger("lev")
    logger.setLevel(logging.DEBUG)
    logger.debug("[lev app - password cracker] log from asset - start point")

    # EXTRACT HASH FROM FILE
    doc = await john.extract_hash(file_to_extract=file_to_extract, 
                dmg2john=dmg2john,
                racf2john = racf2john,
                wpapcap2john=wpapcap2john,
                keepass2john=keepass2john,
                rar2john=rar2john,
                zip2john=zip2john,
                gpg2john=gpg2john,
                hccap2john=hccap2john,
                putty2john=putty2john,
                uaf2john=uaf2john,
                vncpcap2john=vncpcap2john,
                other=other,
                hash_extractor=hash_extractor)
    data = await doc.get()
    logger.debug(f"[lev app - password hash extraction {data['hash']}")

    hash_value = data["hash"]
    print(hash_value)


    # GET CEWL/CUPP WORDLIST
    try:
        doc = await CewlCupp(url=url,
                    depth=depth,
                    min_length=min_length,
                    offsite=offsite,
                    concatenate_cewl = concatenate_cewl,
                    special_chars_cewl = special_chars_cewl,
                    random_nums_cewl = random_nums_cewl,
                    leet_cewl = leet_cewl)
        data = await doc.get()
        wordlist_1 = data["wordlist"]
    except Exception:
        wordlist_1 = '["Hello2_y0u", "a1b2c3"]'

    # # GET CUPP -i WORDLIST:
    try:
        doc = await Cupp_User_Profile(first_name=first_name,
                                                surname=surname,
                                                nickname=nickname,
                                                birthday=birthday,
                                                partners_name=partners_name,
                                                partners_nickname=partners_nickname,
                                                partners_birthday=partners_birthday,
                                                childs_name=childs_name,
                                                childs_nickname=childs_nickname,
                                                childs_birthday = childs_birthday, 
                                                pets_name = pets_name,
                                                company=company,
                                                keywords=keywords,
                                                related_words=related_words,
                                                special_chars=special_chars_prof,
                                                random_nums=random_nums_prof,
                                                leet=leet_prof)
        data = await doc.get()
        wordlist_2 = data["wordlist"]
    except Exception:
        wordlist_2 = ""

    wordlist = wordlist_1 + wordlist_2
    #wordlist = '["Hello2_y0u", "a1b2c3"]'


    # RUN JOHN THE RIPPER
    if data["success"] == True:
        doc = await john.Base(hash_value, wordlist, timeout)
        data = await doc.get()
        logger.debug("Password:")
        logger.debug(data['password'])
