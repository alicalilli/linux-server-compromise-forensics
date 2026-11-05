import struct,sys,datetime,socket
T={1:'RUN_LVL',2:'BOOT',5:'INIT',6:'LOGIN',7:'USER',8:'DEAD'}
d=open(sys.argv[1],'rb').read()
for i in range(0,len(d)-383,384):
  t,_,pid,line,uid,user,host,e1,e2,sess,sec,usec,a0,a1,a2,a3,_u=struct.unpack('<hhi32s4s32s256shhiii4i20s',d[i:i+384])
  s=lambda b:b.split(b'\0')[0].decode('latin1')
  ts=datetime.datetime.fromtimestamp(sec,datetime.timezone(datetime.timedelta(hours=1))).strftime('%Y-%m-%d %H:%M:%S CET')
  if t in (1,2,7,8): print(f"{ts} {T.get(t,t):8} pid={pid:<5} line={s(line):6} user={s(user):9} host={s(host)}")
