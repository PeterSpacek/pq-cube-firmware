#!/usr/bin/env python3

import secube, getpass, sys

def main():
    try:
        id = int(sys.argv[1])
        name = sys.argv[2]
        data = bytearray.fromhex(sys.argv[3])
        if len(sys.argv) > 4:
            validity=int(sys.argv[4])
        else:
            validity=-365*24*3600
    except:
        print("USAGE: add_key.py ID NAME DATA [VALIDITY]")
        return 1
    
    cube=secube.SEcube()
    password=getpass.getpass()
    cube.login(password)
    
    key=secube.SEcubeKey(name=name, id=id, data=data, validity=validity)
    cube.key_edit(secube.SE3_KEY_OP_UPSERT, key)
    cube.logout()
    cube.close()
    return 0
    
if __name__=="__main__":
    exit(main())