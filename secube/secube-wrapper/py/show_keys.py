#!/usr/bin/env python3

import secube, getpass

def main():
    cube=secube.SEcube()
    password=getpass.getpass()
    cube.login(password)
    
    keys=cube.key_list()
    
    for key in keys:
        print("KEY %d"%int(key))
        print("\tNAME %s"%str(key))
        print("\tSIZE %d"%len(key))
        print("\tVALIDITY %d"%key.validity)
        print()
    
    cube.logout()
    cube.close()
    return 0
    
if __name__=="__main__":
    exit(main())