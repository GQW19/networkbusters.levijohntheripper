import logging

import levrt
from lev.networkbusters.john_the_ripper import john


async def main():
    
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


if __name__ == "__main__":
    #logging.basicConfig()
    #logger = logging.getLogger("lev")
    #logger.setLevel(logging.DEBUG)
    #logger.debug("[lev app - hello world] debug test")
    levrt.run(main())
