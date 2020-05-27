#!/usr/bin/env python3
# -*- coding:utf-8 -*-
#
# This file deal with Customized message for RSL10 evaluation board from OnSemi
#
# Copyright (c) 2017 François Wautier
#
# Note part of this code was adapted from PyBeacon (https://github.com/nirmankarta/PyBeacon)
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
# of the Software, and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all copies
# or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR
# IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE

import aioblescan as aios

# Decode customized 128-bit V3 beacon from RSL10 evaluation board
def RSL10v3_decode(packet, UUID=b"\x53\xac\x89\xd1\xec\x35\x5e\xbb\x84\xe1\x8d\xad\xb5\xd4\xdb\x84"):
    """Check a parsed packet and figure out if it is a RSL10V3 Beacon.
    If it is , return the relevant data as a dictionary.

    Return None, it is not a RSL10V3 Beacon advertising packet"""

    ssu=packet.retrieve("Complete uuids")
    found=False
    for x in ssu:
        if UUID in x:
            found=True
            break
    if not found:
        return None

    found=False
    adv=packet.retrieve("Advertised Data")
    for x in adv:
        luuid=x.retrieve("Service Data uuid")
        for uuid in luuid:
            if UUID == uuid:
                found=x
                break
        if found:
            break


    if not found:
        return None

    try:
        top=found.retrieve("Adv Payload")[0]
    except:
        return None
    #Rebuild that part of the structure
    found.payload.remove(top)
    #Now decode
    result={}
    data=top.val
    #etype = aios.EnumByte("type",self.type.val,{ESType.uid.value:"Eddystone-UID",
    #                                        ESType.url.value:"Eddystone-URL",
    #                                        ESType.tlm.value:"Eddystone-TLM",
    #                                        ESType.eid.value:"Eddystone-EID"})
    #data=etype.decode(data)
    #found.payload.append(etype)
    # start message decoding
    # temperature
    myinfo=aios.ShortInt("temperature", 'little')
    data=myinfo.decode(data)
    #found.payload.append(myinfo)
    result["temperature"]=myinfo.val
    # humidity in percentage
    myinfo=aios.UShortInt("humidity", 'little')
    data=myinfo.decode(data)
    #found.payload.append(myinfo)
    result["humidity"]=myinfo.val
    # Pressure
    myinfo_lo=aios.UShortInt("pressure_low", 'little')
    data=myinfo_lo.decode(data)
    myinfo_hi=aios.UIntByte("pressure_low")
    data=myinfo_low.decode(data)
    result["pressure"]=myinfo_lo.val + myinfo_hi.val<<8
    #found.payload.append(myinfo)
    # format version, no need to save
    myinfo=aios.IntByte("version")
    data=myinfo.decode(data)
    #found.payload.append(myinfo)
    # tilt_x value
    myinfo=aios.IntByte("tilt_x")
    data=myinfo.decode(data)
    result["tilt_x"]=myinfo.val
    #found.payload.append(myinfo)
    # tilt_y value
    myinfo=aios.IntByte("tilt_y")
    data=myinfo.decode(data)
    result["tilt_y"]=myinfo.val
    #found.payload.append(myinfo)
    # return RSSI value
    rssi=packet.retrieve("rssi")
    if rssi:
        result["rssi"]=rssi[-1].val
    mac=packet.retrieve("peer")
    # return MAC address
    if mac:
        result["mac address"]=mac[-1].val

    return result
