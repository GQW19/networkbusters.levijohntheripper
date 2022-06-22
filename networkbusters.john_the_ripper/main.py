import logging

import levrt
from lev.networkbusters.john_the_ripper import john


async def main():

    print("----------------------")
    print("Testing Wordlist Rules")
    doc = await john.Wordlist('file1.zip/file1:$pkzip$1*1*2*0*f3*130*baa0c410*0*3f*8*f3*39f1*22010a1c525bca35f000b57301221b4f894eb25ed9b59a57a5b4c7facda3fc687bd0828be76b70a81c9da344ae1ff03db28b38f329b9ba95a0dc27f55a80c6ad016e860d9e39b42373ca34e5e2fe65781152de437d1294cca124ea8631da84b8d610c0b4c46c5ed6bcf9dd39f3b735c795662c87371ef4674e64ee501c4daebadbe35ba996d189e6690f613dabd37b519cc39f0e689078d779f33cfa1bfb7ea26de3d7a6cfcf6562d5c4396035bac2d3ae69ef18288937a2775a815d5db1d491cdff8a792d2bcb6da109cfaef2298bff0d747043eb283945debb7d04221bf5405d6d35910fc560a30993a8977c67eafd9dffca*$/pkzip$:file1:file1.zip::file1.zip', timeout=1000)
    data = await doc.get()
    print(data["msg"])
    print(data["password"])

    """
    print("----------------------")
    print("Testing Simple Hash")
    doc = await john.Incremental('my_file:$pkzip$1*2*2*0*13*7*b042d89e*42*49*0*13*7e8a*dae9818f16b061f65e12f69c83acd3180333b3*$/pkzip$:my_file')
    data = await doc.get()
    print(data["msg"])
    print(data["password"])

    print("----------------------")
    print("Testing Uncrackable Hash")
    doc = await john.Incremental('my_file:$pkzip$1*2*2*0*13*7*b042d89f*42*49*0*13*7e8a*dae9818f16b061f65e12f69c83acd3180333b3*$/pkzip$:my_file')
    data = await doc.get()
    print(data["msg"])
    print(data["password"])
    """

if __name__ == "__main__":
    #logging.basicConfig()
    #logger = logging.getLogger("lev")
    #logger.setLevel(logging.DEBUG)
    #logger.debug("[lev app - hello world] debug test")
    levrt.run(main())
