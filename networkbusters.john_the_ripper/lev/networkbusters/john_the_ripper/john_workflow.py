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
            annot.Param("hash_extractor", "(If Other) Name Of Hash Extractor Tool")]
)
async def john_workflow(file_to_extract: File = None, 
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
                hash_extractor: str=""):
    """
    John Workflow. 
    ```
    await john_workflow(..)
    ```
    """

    import logging
    logging.basicConfig()
    logger = logging.getLogger("lev")
    logger.setLevel(logging.DEBUG)
    logger.debug("[lev app - password cracker] log from asset - start point")

    doc = await john.extract_hash()
    data = await doc.get()
    logger.debug(f"[lev app - password hash extraction {data['hash']}")

    hash_value = data["hash"]

    if data["success"] == True:

        doc = await john.incremental(hash_value)
        data = await doc.get()
        logger.debug(f"[lev app - hello world] {data['msg']}")

        logger.debug("[lev app - hello world] log from asset - end point")