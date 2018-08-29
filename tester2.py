from scapy.all import *



def tester2(pkts):
    i=0;
    payload_full = b""
    # pkts.show()
    for p in pkts:
        if p.haslayer(TCP):
            # print(p.payload)
            print(i)
            i+=1
            payload_full+=(p.payload)
    print ("break \n")
    print(len(pkts[2900].getlayer(Raw)))




    # f.write(str(pkts[2900].getlayer(Raw)))
    print (len(str(pkts[2900].getlayer(Raw))))
    # f.write(str(pkts[2900].getlayer(Raw))) #shows packet 2901 in wirehsark when using 2900

    # print(hexdump(pkts[2900].getlayer(Raw)))

if __name__ =="__main__":
    print("dsa")
    f=open("export_data","w+")
    packets = rdpcap('google check.pcapng')
    tester2(packets)
    print("asdsad")
    f.close()