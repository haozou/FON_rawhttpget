import httplib

conn = httplib.HTTPConnection("www.china-pub.com")
conn.request("GET", "/edition06/imgchk/validatecode.asp")
r = conn.getresponse()
msg_dict = dict(r.msg)
print msg_dict['set-cookie']

file = open('code.bmp', 'wb')
file.write(r.read())
file.close()