# CTE - Week 6

___

## Classroom Links

___

* [Teams](https://teams.microsoft.com/l/team/19%3a7a166f374eb44c89bb972a20cf5a3d6e%40thread.tacv2/conversations?groupId=b0216bab-7ebb-498b-af22-3d7c8db2d92f&tenantId=37247798-f42c-42fd-8a37-d49c7128d36b)  
* [CLME](https://learn.dcita.edu/)
* [CTE_TTPs_Lab_Manual_CTA_1901](.\Files\CTE_TTPs_Lab_Manual_CTA_1901.pdf)

___

## Lesson - Module 2 — Lesson 1 1: Python Modules

### Lesson Overview

### In this lesson we will discuss

* Exception Handling
* Standard Libraries Tour
  * urllib / requests
  * re / BeautifulSoup
  * base64

### Error Handling

* Tidying previous code...
  * The last Python script you wrote would connect to a FTP server.
  * What if the server is down, or cannot be reached?  
  ![Errors](./Files/Images/Lesson11/error1.png)
  * Before we move forward, our script needs a means of **error handling**
* Enter Exceptions:
  * Python error handling uses keywords **try, except, raise, & finally**
  * You handle errors (or **exceptions**) by "**try**-ing" to do something:  
  ![Errors](./Files/Images/Lesson11/error2.png)
  * And that could go smoothly, "**except**" when something goes wrong!
* Be warned!
  * Using a general except statement, any error that occurs will trigger it!  
  ![Errors](./Files/Images/Lesson11/error3.png)
  * Here, even if the server were up, we have an accidental ***attribute error***
* Syntax errors will not be caught
  * However, even with a general **except** statement, syntax errors will show.  
  ![Errors](./Files/Images/Lesson11/error4.png)
  * This will error out and the scritp will ***NOT*** exit gracefully, as before
* Be specific with your exceptions!
  * To avoid catching **any** kind of error, provide a **specific** error type.  
  ![Errors](./Files/Images/Lesson11/error5.png)
* But there are still other errors...
  * What if you need to handle **more than just one** kind of error?  
  ![Errors](./Files/Images/Lesson11/error6.png)
  * In this case, perhaps the server cannot be reached because it is not at all within its range...
* You can handle multiple exceptions easily!
  * To handle these errors the same way, use a **tuple** with **except**.  
  ![Errors](./Files/Images/Lesson11/error7.png)
  * The only remaining case is handling different exceptions in different ways.
* You can be distinct in how multiple errors are handled.  
  ![Errors](./Files/Images/Lesson11/error8.png)
  * To handle multiple errors differently, just add more **except** code blocks.
* And you can generalize these caught exceptions.
  * Any **except** statement can keep track of the exception **object** it caught.
  * So if you want to see the real error message that Python would originally give you, but still gracefully catch the error, you can use this syntax:  
  ![Errors](./Files/Images/Lesson11/error9.png)
* Better visibility on errors and cleaner code
  * The **error** object (or whatever you decide to call it) inherits properties from, at minimum, the Python **BaseException**.
  * That allows you to see the **args** property, which is a **tuple**, like so:
    * **args[0]** = error number
    * **argg[1]** = error message
    ![Errors](./Files/Images/Lesson11/error10.png)
* The other keywords for exception handling: finally

    ```Python
    with socket . socket() as s: 
        try :
        # Connect to the server...
        s.connect (('192.168.229.105',21))
    except (ConnectionRefusedError, OSError) as  error:
        # There was an error! Tell the user.
        print("[!] FAILED to connect with error below: "
        print (error .args)
    finally:
        # Regardless what happens, do this "on the way out " 
        print("The program will continue from here!
    ```

  * The **finally** statement will run after a **try/except** segment, regardless of whether or not an exception has been handled.
* The other keywords for exception handling: raise
  * The raise statement will force a specified error to occur.  
  ![Errors](./Files/Images/Lesson11/error12.png)
  * This is most commonly used when you are writing your own module or classes and are preparing for potential errors that other programmers  might run into.
* Exception Handling Best Practices:
  * Minimize your try blocks.
  * Specify what you are wanting to catch with your except blocks
  * Generalize multiple errors by keeping track of the Exception objects.
  * Test your inputs to see what other exceptions your code should handle.
* Documentation on Exception Handling:
  * For more detailed functionality and syntax examples, view the Python tutorial on Errors and Exceptions: `https://docs.python.org/3/tutorial/errors.html`
  * For other use cases and specific types of exceptions, view the Python documentation on Built-in Exceptions:
`https://docs.python.org/3/library/exceptions.html`

### urllib Module

* socket module reminders:
  * Handle socket objects "with" a context manager.
  * Input and output is simply **send()** and **recv()**
  * Data is transferred in Python **bytes** objects.
* The urilib Module:
  * You have automated the process of working with a network socket.
  * This could be used to connect to port 80.
  * But Python can do better: one of the standard libraries is **urllib**
* urllib: Interacting with the Internet
  * `urllib` — URL handling modules
  * Source code: `Lib/urllib/`
  * `urllib` is a package that collects several modules for working with URLs:
    * `urllib.request` for opening and reading URLs
    * `urllib.error` containing the exceptions raised by `urllib.request`
    * `urllib.parse` for parsing URLs
    * `urllib.robotparser` for parsing robots.txt files
* Reading web pages with urllib.request
  * The `urllib.request` module defines functions and classes which help in opening URLs (mostly HTTP) in a complex world — basic and digest authentication, redirections, cookies and more.
  * `urllib.request.urlopen(url, data=None, [timeout,]*, cafile=None, capath=None, cadefault=False, context=None)`
  * Open the URL url, which can be either a string or a `Request` object.
    * Source: `https://docs.python.org/3.l/library/urllib.request.html`
  * Open web pages by using the **urllib.request.urlopen()** function
* Typically you supply a URL as a string:  
![URLLIB](./Files/Images/Lesson11/urllib1.png)
  * This returns a file-like object, so you will have to **.read()** the contents
* You can use a context manager!  
![URLLIB](./Files/Images/Lesson11/urllib2.png)
  * The response object has plenty of other properties... see documentation!
* By default, you are sending HTTP GET requests.
  * GET is the most common HTTP method, used for retrieving data.
  * To send variables and data in the request with a GET method, you supply them as part of the URL, denoted by a question mark.
  * Data is supplied in the form variable-value, joined by an ampersand.  
  ![URLLIB](./Files/Images/Lesson11/urllib3.png)
* urllib offers functionality to easily put data in that form.
  * The urllib submodule, `urllib.parse` offers a convenient function.
  * `urllib.parse.urlencode()` takes a dictionary as an argument, and will convert it into the HTTP variable form.  
  ![URLLIB](./Files/Images/Lesson11/urllib4.png)
* And urlencode() will encode special characters.
  * Appropriately given the name, the `urlencode()` function will also properly handle special characters passed into a URL.  
  ![URLLIB](./Files/Images/Lesson11/urllib5.png)
* You need to parse your data to make a POST request.
  * To submit data (like filling out a form), you usually make a POST request.
  * This is where the parsing functions come in handy.
  * The data is passed as an argument must be encoded (**as bytes!**)  
  ![URLLIB](./Files/Images/Lesson11/urllib6.png)
* urllib Resources and Reading Material
  * There is much more that the urllib module can do. We only touched upon the basics.
  * For more details, examples, and use cases, look at the official documentation.

`https://docs.pvthon.orq/3/librarv/ur//ib.request.html#module-urllib.request`

* You will have plenty of opportunity to work with urllib in the exercise.

## requests module

* To avoid a lot of the overhead...
  * The urllib module needed prep-work to be done for making requests.
  * A great alternative, that is now seamlessly available to Python 3, is the ***requests*** module.
  * requests turns HTTP methods into their own Python methods:
    * HTTP GET - requests.get("http://example.com")
    * HTTP POST - requests.post("http://example.com")
    * and so on
* Requests returns response objects in a simpler way.  
![Requests](./Files/Images/Lesson11/requests1.png)
  * The `requests` module typically makes for much less code.
* Supplying and accessing data is much faster.
  * If you didn't want to bother putting GET parameters in the right form, the requests module can handle it passed as just a dictionary.  
  ![Requests](./Files/Images/Lesson11/requests2.png)
  * HTTP headers are also returned as a ditionary for easy accesss
* This is just as easy with POST data.
  * You can do the same thing with an HTTP POST method.  
  ![Requests](./Files/Images/Lesson11/requests3.png)
  * You should only POST data to pages supporting that method.
* The requests module can do much more.
  * File upload:
    * `requests. post(url, files = {"filename" : open( "filename"`
  * Decode JSON data:
    * `requests . get(url); print(r.json())`
  * Handle timeouts:
    * `requests.get(url, timeout`
  * Send custom headers or cookies:
    * `r = requests.get(url, headers = h dict, cookies = c_dict)`
  * Basic HTTP authentiction:
    * `requests. get(url, auth = ("username", "password"))`
  * Different HTTP methods:
    * `requests.put(url)`; `requests.patch(url)`; `requests.head(url)`
  * Monitor redirections:
    * `requests.get(url)`; `print(r.history)`
  * Handle sessions and cookies:
    * `requests.Session()`; `s.get(url)`; `print (s. cookies)`
* Cookies can be stored as part of a Session:
  * HTTP cookies can be passed along with a request (last slide). ..
  * Or they can be modified relative to the "Session" they belong to.  
  ![Requests](./Files/Images/Lesson11/requests4.png)
* requests Resources and Reading Material
  * The requests module has a very simple syntax and a lot of functionality.
  * For more details, examples, and use cases, look at the official documentation.

  `http://docs.python-requests.org/en/master/`
  `http://docs.pythonrequests.org/en/master/user/quickstart/`  

  * You will have plenty of opportunity to work with requests in the exercise.

## re (REGEX) Module

* So how do you process data you might get from a site?
  * If you are have a very large string, you likely want to carve things out of it.
  * You can muddle around with the `string.split()` syntax and slicing...
  * But this is often inefficient, and Python can do better.
  * Thankfully, there are modules to help with **text processing**!
* Have you heard of regular expressions?
  * Regular Expressions, or "regek' are strings of text that define a pattern that is used by algorithms to search for text, often used for "find & replace" or input validation.
  * Typically, they look like gibberish.
  * Each character has a special meaning  
  ![REGEX](./Files/Images/Lesson11/regex1.png)
* Python has a built-in re module to work with these.  
![REGEX](./Files/Images/Lesson11/regex2.png)
  * There are a lot of ways to find a match with re. This is only one example.
* Regular Expression Crash Course
  * As a rule, Regex patterns look at each character literally.
  * ***With the EXCEPTION*** of the special characters defined in these tables

Character | Meaning | ex. Pattern | ex. Match
--- | --- | --- | ---
\w | "Word character" (letters, digits, underscores) |  \w\w\w\w | _cT3
\W | **NOT** "word character" | \W\W\W | :-)
\d | Digits (0-9) | version \d.\d | version 2.0
\D | **NOT** digits | \D\D\D | A+B
\s | "Space characters" (tabs, newlines, vertical tab) | a\sb\sc | a b c
\S | **NOT** space characters | S\S\S\S\S\S | DC3CTA
. | Any character | ...... | e1e37!

* Regular Expression Crash Course (greedy)
  * These quantifiers are, by default, "greedy" (match as much as possible)
  * One of the most powerful regex is: **.+** (match any character as much as possible)

Character | Meaning | ex. Pattern | ex. Match
--- | --- | --- | ---
\+ | One or more repeats of the previous character| \w+ | long_w0rds
{3} | Three repeats of the previous character | \d{4} | 1337
{2,4} | Two to four repeats of the previous character | A{2,4} | AA or AAA
{3,} | At least three repeats of the previous character | \W{3,} | AAA
\* | Zero or more repeats of the previous character | A\*B\*C | AACCCC  
? | The previous character once or more (optional) | plurals? | plural
? | Makes quantifiers "lazy" (as little as possible) | hello{3,8}? | hellooo

* Regular Expression Crash Course (Anchors)
  * Captured groups let you select a portion of your pattern match.
  * All these special characters and control make regex very powerful.

Anchor | Meaning | ex. Pattern | ex. Match
--- | --- | --- | ---
^ | Positioned at the start of the string/line.|  | line start
$ | Positioned at the end of the string/line. | . *end$ | line end
[...] | Grouping, one of the characters in the braces |  D[ou] | Dog or Dug
[^...] | One of the characters **NOT** in the braces group | D[^ou]g | Dig
(...) | )Captured grouping, a substring to extract | \<b>(.*)\</b> | bolded text
\| | OR operator in captured groups | (this that) | that
\1 | Contents of captured group #1 | 1TA | DC3CTA

* The re module breaks down into two concepts:
  * Python uses two high-level objects to handle regular expressions:
    * Regex Objects
      * Considered "compiled" patterns, that offer functions to perform operations like search, split and substitute on given text.
      * `regex = re. compile("<b>(.*?)</b>`
    * Match Objects
      * Returned from function calls on regex objects, with properties regarding the matched text like start and end positions.
      * `match regex.match("<b>DC3CTA</b>")`
  * The module also offers convenience functions that do the same the operations as Regex objects, but without "compiling" a pattern.
* Difference in "search ( )" versus "match ( )
  * It is important to know the difference between the search() and match() operations, because you might accidentally trip up:
    * `search()` will look for the first location that matches the given pattern.
    * `match()` will look to see if the beginning of the string matches the given pattern
  * More often than not, you likely want to use the search() function!
* Greedy matching versus lazy matching:  
![REGEX](./Files/Images/Lesson11/regex3.png)
  * Say we had an HTML anchor tag and we wanted to extract the URL. There is the potential to match too much using the default greedy search.
* Often times you will want more than just the first match.
  * To retrieve more than just one result, use
methods like `findall()` or `finditer()`
  * These will return only strings representing the match (not a Match object!) packaged inside of a list.  
  ![REGEX](./Files/Images/Lesson11/regex4.png)
* You can also supply "flags" to tweak even more settings...
  * As an optional keyword argument to most every Regex operation method, you can use flags (constants in the re module) to change the pattern:
  * `re.ASCII` - make **\w, \d, \s** and their variants match only ASCII.
  * `re.MULTILINE` - ensure characters like **^** and **$** match line anchors.
  * `re.DOTALL` force the **.** to match all characters (including newlines)
  * `re.IGNORECASE` - Perform case-insensitive matching.
* re Resources and Reading Material
  * Regular Expressions are extremely versatile and they are used in so many other applications and programming languages!
  * To practice and experiment with more regex, check out: `https://regexr.com/` or `https://gchq.github.io/CyberChef/`
  * For more details, examples, and use cases for the re module, look at the official documentation: `https://docs.python.org/3/library/re.html`

## BeautifulSoup Module

* Use BeautifulSoup for web scraping:
  * The purpose of text processing so far has been strictly web processing... but Regular Expressions are general-purpose and can do so much more!
  * A more tailored library specifically to do web scraping is **bs4**.
  * **bs4** is accessible in Python3. It will take an HTML document and turn it into a tree of Pythonic objects that you can navigate through and manipulate.
* BeautifulSoup lets you extract data through objects.
  * The module will parse through HTML
and offer access to each element and attribute.
  * The most high-level object is the 'BeautifulSoup", and you can drill down from there  
  ![SOUP](./Files/Images/Lesson11/soup1.png)
* It breaks down into four conceptual objects:
  * The module uses...
    1. A Beautiful Soup object, as the top-level tree
    2. A Tag object, as an HTML tag in the original document
    3. A NavigableString, as a bit of text within a tag.
    4. A Comment, as a special errata of a NavigableString.  
![SOUP](./Files/Images/Lesson11/soup2.png)
* BeautifulSoup is handy for finding multiple elements:
  * You can access element (**Tag**) attributes by treating it like a dictionary.
  * This example finds links just as we did with Regex, but is more readable:  
  ![SOUP](./Files/Images/Lesson11/soup3.png)
* Bearutiful Soup Resources and Reading Material
  * We will not go into depth on BeautifulSoup, but you should be aware of its existence as an alternative to web scraping with Regular Expressions
  * For more details, examples, and use cases for the BeautifulSoup Module, look at the official documentation

  `https://www.crummy.com/software/BeautifulSoup/bs4/doc`

  * This may come in handy if you choose this route for the exercise

## base64 Module

* Often times, cyber threats mask themselves:
  * When an attacker or an adversary wants to hide their payload, they will **obfuscate** their code, or the data that they are working with.
  * This can be done in many ways, and some methods offer a stronger means of "protection" in how sophisticated the obfuscation is.
  * Typically this is done to avoid signature detection, or even just to add layers of complexity so defenders are less likely to find the real payload.
* One very common method is simple data encoding.
  * While it is a very weak form of obfuscation, it is certainly the most common: **just encoding data into another form or representation.**
  * This is trivial because the only thing necessary to **de-obfuscate** is to decode the encoded data. Surprisingly, this is extremely prevalent.
A very predictable method is Base64.
  * **Base64** is a binary-to-text encoding scheme that represents data in an ASCII string, using only printable characters, like letters and numbers.
  * It is a form of encoding. For every one string of data decoded, there exists only one string encode and vice versa  
  ![Base64](./Files/Images/Lesson11/base64-1.png)
* Base64 is very recognizable:
  * As a rule, Base64 encoding must have a length as a multiple of four.
  * If an encoding **does not** have a length as a multiple of four, it adds **up to two** trailing equals signs (z) as padding.  
  ![Base64](./Files/Images/Lesson11/base64-2.png)
* Python has a built-in library for it:
  * The base64 module in Python has two
simple functions: b64encode() and b64decode()
  * Python 3 requires the arguments be passed as bytes, so you can prepend your string with a "b" or use the bytes() function.  
  ![Base64](./Files/Images/Lesson11/base64-3.png)
* Base64 is just a number base, like any other:
  * You know base 10 (decimal), base 2 (binary), and base 16 (hexadecimal).
  * They are all just another way to represent the same data. Just as there is Base64, you could also find Base32 or even Base85/Ascii85:
    * Base32 - Uses only uppercase letters and the numbers 2-7. Pads with equal signs to a length as a multiple 8.
      * `base64.b32encode(b"DC3CTA")`
        * `b'IRBTGQ2UIE======'`
    * Base85/Ascii85 - Uses letters, numbers, and punctuation characters. Easily recognizable by a wide use of random punctuation
      * `base64.b85encode(b"Many characters")`
        * b'O<`_%AY*7@a$#e1WpZ-'
* base64 module Resources and Reading Material
  * Base64 and its variants are not conceptually hard to grasp...
  * The priority is instead learning to recognize and identify it when you see it.
  * For more details, examples, and use cases for the base64 module, look at the official documentation.  

  `https://docs.python.org/3.4/1ibrary/base64.html`
  
  * You will have plenty of opportunity to work with base64 in the exercise.

___

### Exercise - Module 2, Lesson 11 – Python Modules

___

[Module 2, Lesson 11 Script File](./Scripts/Python/Mod2L11-Python-Modules.py)  
