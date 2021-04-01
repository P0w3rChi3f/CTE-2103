###################################################
# Variables
###################################################
port = 22
banner = 'SSH Server'
print('Checking for ' + banner + ' on port ' + str(port))

type(port) #determine what type of variable "port" is

port_list = [21,22,111,53,69,80,110,443,139,138,137,445,5353,
8080]
type(port_list)

port_open = True
type(port_open)

###################################################
# Numbers
###################################################

42/2
4*2
4**2
4.200000
int(2.3)
float(3)
2 - 44
4 % 3
4 % 2

x = 1
type(x)

x=1.1
type(x)

###################################################
# Strings
###################################################

jhopper = "Mornings are meant for"
jhopper

print(jhopper)

print(jhopper.lower())

print(jhopper.upper())

print(jhopper.replace("Mornings","Nights"))

print(jhopper + " coffee and contemplation.")

first_line = "Now Flo, "
next_line = " coffee and contemplation"
print(jhopper + "{}".format(next_line))

print(("{} " + jhopper + " {}").format(first_line,next_line))

print(("{} {} {}").format(first_line,jhopper,next_line))

print(jhopper.find("are"))

his_quote = first_line + jhopper + next_line
his_quote

netflix = input("What's your favorite Netflix Originals show? ")

netflix

netflix.upper()

response = input("What does 10 + 1 equal? ")

type(response)

response = int(input("What does 10 + 1 equal? "))

print(response)

type(response)

#at the end of each line in my_docstring press the enter key for a new line.
my_docstring = '''This is my first docstring. For
more information on docstrings, visit python.org and
look for PEP 257'''
my_docstring

name = 'Tsheahan' #this is an example of an f-string 
f'{name} loves Baltimore.'

# 3. Now create a new string “www.trythis.com” and manipulate it with lstrip() to remove the “www.”. Provide the syntax for the steps taken.

strip_string = "www.trythis.com"
strip_string.lstrip("www.")


# 4. Use the same string to remove the .com with rstrip().
(strip_string.lstrip("www.")).rstrip(".com")

# 5. Create a new string and use the previously learned methods to manipulate the string. Share with the class what was created and the syntax and steps taken.
mystr = "This is my new string"
mystr.lstrip('This ').rstrip(' string')
'my new'

# 6. Pass the variable that was created in the previous step through dir().
dir(mystr)

# 7. Examine the methods available to the newly created string. Some of the methods shown like .find, .upper, and .replace should be familiar since they were used in the walk-through. Provide the syntax used to see the methods available to the string.

# 8. Use help() to learn how to use the method .startswith on the recently created string type variable. Prepare to share with the class the syntax used to get help on the method .startswith. Additionally, provide an example of using the .startswith method.
help(mystr.startswith)

#11. Create variables x, y, and z with the corresponding values of red, white, and blue.
x = 'red'
y = 'white'
z = 'blue'
#12. Utilize those variables in a f-string in conjunction with a method that would capitalize only the first letters of red, white, and blue. The f-string should print out ‘I love the Red White and Blue.’ What was the syntax used?

f'I love the {x.capitalize()}, {y.capitalize()} and {z.capitalize()}'

###################################################
# Lists - part 1
###################################################

things_list = ['mike','dustin','lucas','will']
things_list

things_list.append('barb') 
print(things_list)

things_list.append(11) #python recognizes 11 as an int 
things_list

things_list.remove('barb') 
things_list # output lis line 15

# following line starts line 17
captains = list() #this uses list to evoke an empty list on variable 
captains
captains.append('kirk') 
captains.append('picard') 
captains.append('archer')
captains

# 3. In line 17, the empty list captains was created. Three items were added to the list. Add the item sisko to the list. What was the syntax used?
captains.append('sisko')

# 4. Change list so that the items in the list are alphabetical. What syntax was used?
captains.sort()
# ['archer', 'kirk', 'picard', 'sisko']

# 5. Add the item janeway to the list but make sure that it falls between the items kirk and picard. What syntax was used?
captains.insert(2, 'janeway')
# ['archer', 'kirk', 'janeway', 'picard', 'sisko', 'janeway']

# 6. Delete the item archer from the list. What was the syntax used?
captains.remove('archer')

# 7. In line 15 of the walk-through, things_list shows 5 items in the list. Using only one command, add the items steve, jonathan, nancy, and mad max. What was the syntax used?
things_list.extend(['steve', 'jonathan', 'nacy', 'mad max'])


# 8. Replace the item mad max with the item max using only one command. What was the syntax used?
things_list[-1] = things_list.insert(-1, 'item max')

# 9. Execute things_list.sort(). What error occurs?


###################################################
# Lists - part 2
###################################################

port_list = [21, 22, 111, 53, 69, 80, 110, 443, 139, 138, 137, 445]
print(port_list)

port_list.append(25) 
port_list.append(23) 
port_list.append(88) 
print(port_list)

port_list.sort() #sorts the list numerically from least to greatest
port_list

pos = port_list.index(53) #finds where port 53 is indexed in the list 
pos

print("There will be " + str(pos) + " ports scanned before reaching port 53.")

port_list[4]

port_list[:4] #slices the list to provide the ports that precede port 53

port_list[-1] #provides the last item listed in the list

len(port_list)

port_list[0:15:3]

cnt = len(port_list)
print("I am scanning {} total ports".format(cnt))

port_list.append(8080)
print("I am scanning {} total ports".format(cnt))

###################################################
# Lists - part 3
###################################################

1.
some_nums = range(7)
some_nums
2.
# 3. range(0, 7)
4.
print(some_nums)
# 5. range(0, 7)
6.
list(some_nums)
# 7. [0, 1, 2, 3, 4, 5, 6]
8.
more_nums = range(7,14)
list(some_nums)
9.
# 10. [0, 1, 2, 3, 4, 5, 6]
11.
list(more_nums)
# 12. [7, 8, 9, 10, 11, 12, 13]
13.
evens = range(0,42,2)
list(evens)
14.
# 15. [0, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30, 32, 34, 36, 38, 40]
16.
odds = range(1,42,2)
list(odds)
17.
# 18. [1, 3, 5, 7, 9, 11, 13, 15, 17, 19, 21, 23, 25, 27, 29, 31, 33, 35, 37, 39, 41]
19.
both = evens + odds
#20. Traceback (most recent call last): 
#21.   File "<pyshell#4>", line 1, in <module> 
#22.      both = evens + odds 
#23.  TypeError: unsupported operand type(s) for +: 'range' and 'range'
24.
both = list(evens) + list(odds)
both
25.
#26. [0, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30, 32, 34, 36, 38, 40, 1, 3, 5, 7, 9, 11, 13, 15, 17, 19, 21, 23, 25, 27, 29, 31, 33, 35, 37, 39, 41]

###################################################
# Tuples & Sets
###################################################

1.
wb = ('yakko','wakko','dot') #this is the pythonic way of making a tuple
type(wb)

2.
#3. <class 'tuple'>
4.
dsny = tuple(['huey','dewey','louie']) #not pythonic, causes confusion w ([])
type(dsny) #but syntax still works as a tuple
5.
#6. <class 'tuple'>
7.
amigos = 'Chase','Short','Martin' #not pythonic, but works
type(amigos)
8.
#9. <class 'tuple'>
10.
11.
one = (1,) #pythonic way of creating tuple with only one item
12.
13.
empty = tuple() #this is an empty tuple
14.
15.
others = {'lawford','bishop'} #this is an example of a set
16.
rats = {'sinatra','davis','martin','lawford','bishop'}
17.
known = rats - others
18.
known
#19. {‘martin’, ‘sinatra’, ‘davis’}

###################################################
# Dictionaries Part 1
###################################################

1.
tel = {"joyce":1306, "will":1307, "john":1308}
print(tel)
2.
#3. {'joyce': 1306, 'will': 1307, 'john': 1308}
4.
tel["bob"]=1309 #the syntax is: dictionary_name[key]="value"
print(tel)
5.
#6. {'joyce': 1306, 'will': 1307, 'john': 1308, 'bob': 1309}
7.
tel['bob'] #see the value for bob
#8. 1309
9.
print("The value paired with the key bob is", tel['bob'])
#10. The value paired with the key bob is 1309
11.
tel.keys()
#12. dict_keys(['joyce', 'will', 'john', 'bob'])
13.
tel.values()
#14. dict_values([1306, 1307, 1308, 1309])
15.
tel.items()
#16. dict_items([('joyce', 1306), ('will', 1307), ('john', 1308), ('bob', 1309)])
17.
del tel['bob'] #deletes the key:value pair
tel.items()
18.
#19. dict_items([('joyce', 1306), ('will', 1307), ('john', 1308)])
20.
tel
#21. {'joyce': 1306, 'will': 1307, 'john': 1308}
22.
list(tel)
#23. ['joyce', 'will', 'john']
24.
sorted(tel)
#25. ['john', 'joyce', 'will']
26.
'will' in tel #using the in statement to check for membership
#27. True
28.
'bob' in tel
#29. False

###################################################
# Dictionaries Part 2
###################################################

30.
services = {"ftp":21, "ssh":22, "smtp":25, "http":80}
services
31.
#32. {'ftp': 21, 'ssh': 22, 'smtp': 25, 'http': 80}
33.
services.keys()
#34. dict_keys(['ftp', 'ssh', 'smtp', 'http'])
35.
services.values()
#36. dict_values([21, 22, 25, 80])
37.
services.items()
#38. dict_items([('ftp', 21), ('ssh', 22), ('smtp', 25), ('http', 80)])
39.
'ftp' in services
#40. True
41.
print("Found vuln with FTP on port " + str(services['ftp']))
#42. Found vuln with FTP on port 21

###################################################
# Dictionaries Part 3
###################################################

#5. Add the key:value pair of sunrpc:111 to the services dictionary. What syntax was used?

#6. Create a second dictionary named services2. Add the key:value pairs of netbios-ns:137, netbios-dgm:138, and netbios-ssn:139 to the services2 dictionary. What syntax was used?

#7. Merge the services dictionary with services2 dictionary. What syntax was used?