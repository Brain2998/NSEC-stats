import dns.name
import dns.query
import dns.dnssec
import dns.message
import dns.resolver
import dns.rdatatype
import MySQLdb
import sys

db = MySQLdb.connect(host='127.0.0.1', user=sys.argv[1], passwd=sys.argv[2], db=sys.argv[3])
cur=db.cursor()

with open('tlds-alpha-by-domain.txt') as f:
    domains=f.read().splitlines()

for domain in domains:
    queryname=domain+'.'    
    request = dns.message.make_query('asdazxciop.'+queryname, dns.rdatatype.A, want_dnssec=True)
    response = dns.query.udp(request,'192.168.1.3')
    NSEC=''
    #if response=3 NSEC3 is returned, if 0 - wildcard, if 2 - SERVFAIL    
    if (response.rcode()==2):
        response = dns.query.udp(request,'1.1.1.1')
    if (response.rcode()==3 or response.rcode()==0):
        #finding rrset with NSEC record
        for rrset in response.authority:
            if (str(rrset).find(' NSEC')>0):
                NSEC=str(rrset)
                break
        if (NSEC==''):
            nsectype='NOSEC'
        else:    
            nsectype=NSEC[NSEC.index('NSEC'):NSEC.index('NSEC')+5]
        if (nsectype=='NSEC3'):
            hashIterStartIndex=NSEC.index(nsectype)+10
            hashIterEndIndex=hashIterStartIndex
            while (NSEC[hashIterEndIndex]!=' '):
                hashIterEndIndex+=1
            hashiter=NSEC[hashIterStartIndex:hashIterEndIndex]
            saltstartindex=hashIterEndIndex+1
            saltendindex=saltstartindex
            while (NSEC[saltendindex]!=' '):
                saltendindex+=1
            salt=NSEC[saltstartindex:saltendindex]
            if (salt=='-'):
                saltlength=0
            else:    
                saltlength=len(salt)    
        else:
            hashiter=0
            salt='-'
            saltlength=0
        sql="INSERT INTO tldnsec (domain_name, nsec, salt_length, salt, hash_iterations) VALUES (%s, %s, %s, %s, %s)"
        val = (domain,nsectype,str(saltlength),salt,hashiter)
        cur.execute(sql, val)
        db.commit()
        print(queryname)
    else:
        print(queryname+" status: "+str(response.rcode()))

db.close()    
