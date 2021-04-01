###################################################
# Part 1
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
# Part 2
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
# Part 3
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
(strip_string.lstrip("www.")).rstrip(".com")

# 4. Use the same string to remove the .com with rstrip().

# 5. Create a new string and use the previously learned methods to manipulate the string. Share with the class what was created and the syntax and steps taken.

# 6. Pass the variable that was created in the previous step through dir().

# 7. Examine the methods available to the newly created string. Some of the methods shown like .find, .upper, and .replace should be familiar since they were used in the walk-through. Provide the syntax used to see the methods available to the string.

# 8. Use help() to learn how to use the method .startswith on the recently created string type variable. Prepare to share with the class the syntax used to get help on the method .startswith. Additionally, provide an example of using the .startswith method.

# 9. Choose another method that has not been used yet and is available to the string currently be manipulated. Avoid using dunders. Dunders are the words that are sandwiched between two underscores. Feel free to do research on dunders, but right now focus on the other methods available and dunders will be addressed later. Passing methods though help() or searching the internet might be necessary, but choose only one new method and prepare to explain the method to the class. Include syntax and benefits in using the method.

#10. This step is independent from the last three steps that were completed. It will highlight the need and functionality of escaped characters. Save the following lines as a variable named quotes. Then print quotes and make sure to include the indentation, spacing, and line separation:

# I found the following quote in C:\Users\Documents\“Quotes.txt” “Our greatest fear should not be of failure…
# but of succeeding at things in life that don’t really matter.”
# -Francis Chan

#11. Create variables x, y, and z with the corresponding values of red, white, and blue.

#12. Utilize those variables in a f-string in conjunction with a method that would capitalize only the first letters of red, white, and blue. The f-string should print out ‘I love the Red White and Blue.’ What was the syntax used?
