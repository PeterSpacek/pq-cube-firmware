#!/usr/bin/env python3

import secube

if __name__=="__main__":
    devices=secube.SEcube.discover()
    for i,device in enumerate(devices):
        print("DEVICE #%d"%i)
        print("\tPATH: %s"%device.path)
        print("\tHELLO: %s"%repr(device.hello))
        print("\tSERIAL: %s"%("".join(map(lambda x:"%02x"%x,list(device.serialno)))))
        print("\tSTATUS: %d"%device.status)
