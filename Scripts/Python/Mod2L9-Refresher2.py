################################################
# Conditionals & Iterations
################################################

a = 42
b = 5
if a > b: #this statement executes if it evaluates to True
  print("a is greater than b") #note the indentation


if a > b: #this statement executes if it evaluates to True 
    print("a is greater than b")   
elif a == b: #elif is never reached because the first statement is True
    print("a and b are equal")
else: #else is not reached because the first statement evaluated as True
    print("b is greater than a")

i = 1 #using the while loop 
while i < 7:
    print(i)
    i += 1 #the loop continues till evaluating to False

i = 1 #using the while loop with a break 
while i < 7:
    print(i) 
    if i == 3:
        break #the loop is exited once the if statement evaluates to True
    i += 1 #the loop continues till evaluating to False

i = 0 #using the while loop with a continue 
while i < 6:
    i += 1
    if i == 3:
        continue
    print(i) #the loop continues till evaluating to False

doctor = [1,2,'red','blue'] #create list with integers and strings 
x = 0 #creates a variable
last_indexed = len(doctor) -1 #the variable is one less the length of doctor
while x <= last_indexed: #last_indexed is set to 3 via the previous variable
    doc = doctor[x] #[x] pulls the item from index position 0 
    print(doc,'fish') #print prints the first indexed item and fish
    x = x+1 #x increments by 1 and the loop continues till evaluating to False

houses = ["stark","lannister", "tyrell"] #create list
for x in houses: #x is an arbitrary variable used to iterate through houses
    print(x)

houses = ["stark","lannister", "tyrell"]
for house in range(len(houses)): #loop over indices of the items in a list
    print(house, houses[house]) #prints index and value in that index location

houses = {"stark":"of winterfell" ,"lannister":"of casterly rock" , "tyrell":"of highgarden"} #create dictionary
for k, v in houses.items(): #looping through a dictionary
    print(k, v) #prints key:value pair

#3. Type help() into the interpreter.

#4. Create a docstring with the content of the fourth paragraph in the help() menu. Name the docstring fourth. (Do not retype the paragraph. Copy and paste the paragraph.)

fourth = """To get a list of available modules, keywords, symbols, or topics, type
"modules", "keywords", "symbols", or "topics".  Each module also comes
with a one-line summary of what it does; to list the modules whose name
or summary contain a given string such as "spam", type "modules spam"."""

#5. Create a variable foo and make the value fourth.split().
foo = fourth.split()

#6. Find out what type of variable it is. What was the result?
type(foo)
# <class 'list'>

#7. Create an empty list and set it to the variable removed_words. What was the syntax used?
removed_words = []

#8. Iterate through foo to append all the words to the variable removed_ words but do not include the words ‘a’ and ‘list’ in removed_words. What was the syntax used?
for word in foo:
    if word != 'a':
        if word != 'list':
            removed_words.append(word)
    else:
        continue
print(removed_words)

#9. The variables removed_words and foo should have the same content, except foo also has ‘a’ and ‘list’. Iterate through removed_words, find all the words that foo and removed_words have in common and remove them from foo. What syntax was used?
for word in removed_words:
    if word in foo:
        #print(word)
        foo.remove(word)
print(foo)

#10. What is the output of print(foo)?

# ['a', 'list', 'a', 'list', 'a']

################################################
# Functions
################################################

def my_func():
    print("Hello")

my_func() #to call a function, use function name followed by parentheses

def my_func(artist):
    print("Funk Master " + artist)
my_func("Bootsy Collins")

my_func("Rick James")

my_func ("George Clinton")

def pizza(topping = "peppers"): #uses a default parameter value 
    print("I like my pizza with " + topping)
pizza("onions")

pizza() #without parameters will use default parameters

pizza("anchovies")

def maths(x):
    return 5 * x
print(maths(1))

print(maths(5))

print(maths(2))

#3. Create a function named excited. The function should print an exclamation mark after any word that is passed through the function. For example, the output of excited(‘monkey’) would result in monkey!. What syntax was used?

def excited(x):
    print(x+"!")

excited('monkey')
excited("dog")
#4. Create a function named pizza. The function should print, “I like my pizza with,” and two toppings typically found on pizza. The sentence should end with an exclamation mark. If no arguments are passed through the function, then the default toppings should be pepperoni and sausage. If no arguments are passed through the function, the output of the function should look like: "I like my pizza with pepperoni and sausage!" If arguments are passed through the function, the output will look like the above, but with whatever arguments the user passed through. What syntax was used to create this function?

def pizza(x = 'pepperoni',y = 'sausage'):
    print('I like my pizza with '+x+' and '+y)

pizza()
pizza('pickels','mustard')

#5. Create a function named basic_func. The function should print out a greeting followed by a request for the user’s name. The function will use the user’s name in a following sentence. What syntax was used?

def basic_func(name = None):
    if name is not None:
        print(f'how are you {name}?  Nice to meet you.')
    else:
        name = input('What is your name? ')
        print(f'how are you {name}?  Nice to meet you.')

basic_func()