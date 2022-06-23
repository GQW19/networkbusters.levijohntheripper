from levrt import ctx, annot, Concurrent, File
from . import john

@annot.meta(
    desc = "Run John the Ripper",
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
            annot.Param("timeout", "John: Timeout")]
)
async def Base_Workflow(file_to_extract: File = None, 
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
                wordlist: str = "[]",
                timeout: int = 10):
    """
    John Workflow. 
    ```
    await Base_Workflow(..)
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


    # RUN JOHN THE RUPPER
    if data["success"] == True:
        doc = await john.Base(hash_value, wordlist, timeout)
        data = await doc.get()
        logger.debug("Password:")
        logger.debug(data['password'])