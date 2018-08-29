from scapy.all import *


def pkt_sorter(packets):
    print("start")

    for p in packets:
        # print("reading packets")
        if  p.haslayer(DNSQR) and p.haslayer(DNSRR):
            # print("packet response")
            a_count = p.ancount

            i = 0
            # print(i)
            p.show()
            print("this is the count",a_count,"i equals %d" %i)
            print(p.qd.qname)
            f.write("%s " %str(p.qd.qname))
            while i < a_count:
                # print (p[0][i].rdata, p[0][i].rrname)
                print(p.an[i].rdata)
                f.write("%s"%str(p.an[i].rdata))
                # ans[counter][i]=p.an[i].rdata
                # print ("rdata:"+str(p.ttl))


                i += 1
            f.write("\n")
        print("GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG")




if __name__ =="__main__":
    print("dsa")
    f=open("list_ip_example2.txt","w+")
    packets = rdpcap('example2.pcap')
    pkt_sorter(packets)
    print("part 1 done")
    f.close()
    packets = rdpcap('google check.pcapng')
    f = open("list_ip_google.txt", "w+")
    pkt_sorter(packets)
    print("part 2 done")
    f.close()