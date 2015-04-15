import optparse
import dns.resolver
import threading
import Queue
import sys
import os
from optparse import OptionParser

class dnsinfo:
    def __init__(self,target,domainfile,thread_num):
        self.queue=Queue.Queue()
        self.target=target
        self.domainfile=domainfile
        self.thread_num=thread_num
        self.lock=threading.Lock()
        self.subcount=0
        self.load_domain()
        self.resolvers=[dns.resolver.Resolver() for i in range(thread_num)]

    def  load_domain(self):
        with open(self.domainfile) as f:
            for line in f:
                sub=line.strip()
                if sub:
                    self.subcount+=1
                    self.queue.put(sub)


    def scan(self):
        thread_id=int(threading.currentThread().getName())
        #{target}.com
        if(any(self.target) and self.target!="xxx.com"):
            T_Aresult=[];T_MXresult=[];T_NSresult=[];T_CNAMEresult=[];
            try:
                #Address
                sub=self.target
                A=dns.resolver.query(sub,'A')
                for i in A.response.answer:   
                    for j in i.items:    
                        if(j.address not in T_Aresult):
                            T_Aresult.append(j.address)
                        else:
                            pass
                #Mail Exchange
                MX=dns.resolver.query(sub,'MX')
                for i in MX:
                        T_MXresult.append("MX preference =%s  mail exchanger =%s"%(i.preference,i.exchange))
                
                #NS
                NS=dns.resolver.query(sub,'NS')
                for i in NS.response.answer:
                    for j in i.items:
                        if(j not in T_NSresult):
                            T_NSresult.append(j)
                
                #CNAME
                try:
                    CNAME=dns.resolver.query('www.'+sub,'CNAME')
                    for i in CNAME.response.answer:
                        for j in i.items:
                            T_CNAMEresult.append(j)
                except Exception,e:
                    pass

                print "%s\nDns Address:\n%s\n"%(sub,T_Aresult)

                print "DNS Mail Exchange:"
                for T_MXresult0 in iter(T_MXresult): 
                    print T_MXresult0

                print "\nNS:"
                for T_NSresult0 in iter(T_NSresult):
                    print T_NSresult0.to_text()        

                
                print "\nCNAME:"
                try:
                    for T_CNAMEresult0 in iter(T_CNAMEresult):
                        print T_CNAMEresult0.to_text()
                except Exception,e:
                    pass

            except Exception,e:
                print "error%s"%e
                pass

        #-f domainfile.txt
        elif(self.target=="xxx.com" and os.path.exists(self.domainfile)):
            F_Aresult=[];F_MXresult=[];F_NSresult=[];F_CNAMEresult=[];
            while (self.queue.qsize()>0):

                try:
                    sub=self.queue.get()
                    #Address
                    A=self.resolvers[thread_id].query(sub,'A')
                    for i in A.response.answer:
                        for j in i.items:
                            if(j.address not in F_Aresult):
                                F_Aresult.append(j.address)
                            else:
                                pass


                    #Mail Exchange
                    MX=self.resolvers[thread_id].query(sub,'MX')
                    for i in MX:
                        F_MXresult.append("MX preference =%s  mail exchanger =%s"%(i.preference,i.exchange))

                    #NS
                    NS=self.resolvers[thread_id].query(sub,'NS')
                    for i in NS.response.answer:
                        for j in i.items:
                            if(j not in F_NSresult):
                                F_NSresult.append(j)

                    #CNAME
                    try:
                        CNAME=self.resolvers[thread_id].query('www.'+sub,'CNAME')
                        for i in CNAME.response.answer:
                            for j in i.items:
                                if(j not in F_CNAMEresult):
                                    F_CNAMEresult.append(j)
                    except Exception,e:
                        pass

                    print "%s\nDns Address:\n%s"%(sub,F_Aresult)   

                    print "DNS Mail Exchange:\n"
                    for F_MXresult0 in iter(F_MXresult):
                        print F_MXresult0

                    print "\nNS:"
                    for F_NSresult0 in iter(F_NSresult):
                        print F_NSresult0

                    print "\nCNAME:"
                    try:
                        for F_CNAMEresult0 in iter(F_CNAMEresult):
                            print F_CNAMEresult0
                    except Exception,e:
                        print "NOCNAME"
                except Exception,e:
                    print "error%s"%e
                    pass



    def run(self):
        print "\ndnsinfo.py Result:\n"
        if(any(self.target) and self.target!="xxx.com"):
            for i in range(1):
                t=threading.Thread(target=self.scan,name=str(i))
                t.start()
        elif(self.target=="xxx.com" and os.path.exists(self.domainfile)):
            for i in range(self.thread_num):
                t=threading.Thread(target=self.scan,name=str(i))
                t.start()


if __name__ == '__main__':
    parser=optparse.OptionParser('usage: dnsinfo.py {target}.com  or  dnsinfo.py -f domainfile.txt \n1ovelli\n')
    parser.add_option('-f','--file',dest='domainfile',default='domainfile.txt',type='string',help='File for domain. Default is domainfile.txt')
    parser.add_option('-t','--thread',dest='thread',default='10',type='int',help='Number of threads.Default is 10')
    (options,args)=parser.parse_args()
    if (len(args)>=0):
        parser.print_help()
        #sys.exit(0)
    if(any(args)):
        d=dnsinfo(target=args[0],domainfile=options.domainfile,thread_num=options.thread)
    else:
        d=dnsinfo(target="xxx.com",domainfile=options.domainfile,thread_num=options.thread)

    d.run()
