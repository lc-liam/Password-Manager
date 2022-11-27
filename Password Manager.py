#Gave the Ok to not have canvases and images
from tkinter import *
import sqlite3, hashlib
import random
from tkinter import ttk
from functools import partial
#Database code
with sqlite3.connect("password_manager.db") as db:
    cursor = db.cursor() # controls database

cursor.execute("""
CREATE TABLE IF NOT EXISTS masterPassword(
id INTEGER PRIMARY KEY,
password TEXT NOT NULL);
""")
#This basically creates a table to store the masterPassword, CREATE TABLE IF NOT EXISTS means it will only make it if it doesn't exist already,
#id INTEGER PRIMARY KEY gives a unique id to every entry and password TEXT NOT NULL makes it so you have to put in a password for it to create table.
cursor.execute("""
CREATE TABLE IF NOT EXISTS info(
id INTEGER PRIMARY KEY,
website TEXT NOT NULL,
username TEXT NOT NULL,
password TEXT NOT NULL);
""")

def exit():
    root.destroy() #Closes program
def hashPassword(input):
    hash = hashlib.md5(input) #Runs password through a hash
    hash = hash.hexdigest() #Rreturns as string double length, only has hexadecimal digits

    return hash

def signUpScreen():
    def savePassword():
        if passwordEntry.get() == passwordConfirm.get(): #If passwords in the two entry boxes are the same
            hashedPassword = hashPassword(passwordEntry.get().encode('utf-8')) #hashes password

            insert_password = """INSERT INTO masterPassword(password)
            VALUES(?) """
            #Inserts password into database
            cursor.execute(insert_password, [(hashedPassword)]) #executes the command above
            db.commit() #Saves it to db file
            signUp.destroy() #closes signUp window

        else:
            error.config(text="Passwords entered do not match", bg='red') #Changes error label to display error message
    signUp = Toplevel(root) #Creates new window named signUp
    signUp.title("Sign-up")
    signUp.geometry("400x218")

    name = Label(signUp, text="Liam's Password Manager", pady=10)  # pady adds extra space on the top and bottom of the text
    name.pack()

    passwordText = Label(signUp, text="Create password")  # Creating a window that contains text
    passwordText.config(anchor=CENTER)  # Placing window anchored to the center
    passwordText.pack()  # Updating canvas to place window

    passwordEntry = Entry(signUp, width=20) # Creates entry box
    passwordEntry.pack()
    passwordEntry.focus()  # when launching it already is selected on the text box

    confirmation = Label(signUp, text = "Confirm password")  # Creating a label that contains text
    confirmation.pack()  # Updating canvas to place window

    passwordConfirm = Entry(signUp, width=20) # Creates entry box
    passwordConfirm.pack()

    error = Label(signUp) #Creates empty label
    error.pack()

    registerButton = Button(signUp, text = "Register", command=savePassword) # Creates button
    registerButton.pack(pady = 10) # Packs it with space on the top and bottom



def loginScreen():
    def getMasterPassword():
        checkHashedPassword = hashPassword(password.get().encode('utf-8')) # Encodes password
        cursor.execute("SELECT * FROM masterPassword WHERE password = ?", [(checkHashedPassword)]) #Checks to see if there is a password that matches whatever you put in the box
        return cursor.fetchall() #returns the password from table


    def checkPassword():
        match = getMasterPassword()

        if match:  # if a password matching the database was found then it proceeds to the application
            main()
        else:
            password.delete(0, 'end')  # deletes text if you typed incorrect password
            error.config(text="Incorrect password") #Turns empty label into text

    root.title("Login Screen")

    root.geometry("500x218") # sets the dimensions of the window
    name = Label(root, text="Liam's Password Manager", pady = 10) #pady adds extra space on the top and bottom of the text
    name.pack()

    enterText = Label(root,text = "Enter Password") #Creating a window that contains text
    enterText.config(anchor=CENTER) #Placing window anchored to the center
    enterText.pack() #Updating canvas to place window

    password = Entry(root, width = 20, show="*") #show * makes it so you cannot see the password entered
    password.pack()
    password.focus() # when launching it already is selected on the text box

    error = Label(root)  # Creating an empty label
    error.pack()  # Updating canvas to place window
    exitButton = Button(root, text='Exit!', command=exit) # Creates button
    exitButton.place(x= 10,y= 180) #places button


    btn = Button(root,text="Login", command=checkPassword) # When you click login button it checks if you put in the right password
    btn.pack(pady=5)

    btn1 = Button(root, text = "Sign-up", command = signUpScreen) #When clicked will bring to sign-up screen
    btn1.pack(pady=10) #pady creates spacing between buttons



def addData():
    def addition():
        #This code is responsible for getting the information from the text boxes
        userData = username.get()
        passData = password.get()
        webData = website.get()
        if len(userData) != 0 and len(passData) != 0 and len(webData) != 0: # If all have been filled
            insert_fields = """INSERT INTO info(website, username, password)
            VALUES(?, ?, ?)"""  # Matches corresponding info to correct table
            cursor.execute(insert_fields, (webData, userData, passData))  # Puts info into database
            db.commit()  # updates  database
            detail.destroy() # Destroys detail window
            main() # Calls main part of application
        else:
            error.config(text="Please enter all fields", bg='red') # Changes empty label to display text

    def generate():
        sample_string = '19!wesdfdsfosfe3219'  # define the specific string
        # define the condition for random string
        passLength = int(spin_box.get()) #Retrieves info from spinbox
        result = ''.join((random.choice(sample_string)) for x in range(passLength)) #Responsible for generating random string
        password.delete(0, 'end') #Deletes pre-existing text from password entry box
        password.insert(0, result)  #Inserts generated password into entry box
    detail = Toplevel(root) # Creates new window

    detail.title("Add/Update Entry") # Names window
    detail.geometry("640x200") # Sets dimensions for window
    web = Label(detail, text="Website")  # Creating a label that contains text
    web.grid(row = 1, column=0, pady = 10) # Places text onto a grid format
    website = Entry(detail, width=20) # Creates entry box
    website.grid(row = 3, column=0, padx = 50)

    user = Label(detail, text="Username")  # Creating a window that contains text
    user.grid(row = 1, column=1, pady = 10)

    username = Entry(detail, width=20) # Creates entry box
    username.grid(row = 3,column=1, padx = 50)

    passW = Label(detail, text="Password")  # Creating a window that contains text
    passW.grid(row = 1, column=2, pady = 10)

    password = Entry(detail, width=20) # Creates entry box
    password.grid(row = 3, column=2, padx = 50)
    error=Label(detail) # Creates empty label
    error.grid(row = 4, column=1)


    add = Button(detail, text = "Add", command = addition) #Creates add button
    add.grid(row = 6, column = 1, pady = 30) #Places button

    generateButton = Button(detail, text = "Generate Password", command = generate) # Creates button
    generateButton.grid(row = 6, column = 2, pady = 30)
    #This will be used to determine how long they want password
    spinboxValue = StringVar(value = 0) #Used to store the values of the spinbox
    spin_box = ttk.Spinbox(detail, from_= 10, to= 20, textvariable = spinboxValue, wrap = True) # Creates spinbox
    spin_box.grid(row = 5, column = 2, pady = 10)

    length = Label(detail, text = "Please determine password length: ") # Creates label with text
    length.grid(row = 5, column = 1, padx = 5)

def keybindDetails(input):
    def addition():
        #This code is responsible for getting the information from the text boxes
        userData = username.get()
        passData = password.get()
        webData = website.get()
        if len(userData) != 0 and len(passData) != 0 and len(webData) != 0:  # If all have been filled
            insert_fields = """INSERT INTO info(website, username, password)
            VALUES(?, ?, ?)"""  # Matches corresponding info to correct table
            cursor.execute(insert_fields, (webData, userData, passData))  # Puts info into database
            db.commit()  # updates  database
            detail.destroy()  # Destroys detail window
            main()  # Calls main part of application
        else:
            error.config(text="Please enter all fields", bg='red')  # Changes empty label to display text

    def generate():
        sample_string = '19!wesdfdsfosfe3219'  # define the specific string
        # define the condition for random string
        passLength = int(spin_box.get()) #Retrieves info from spinbox
        result = ''.join((random.choice(sample_string)) for x in range(passLength)) #Responsible for generating random string
        password.delete(0, 'end') #Deletes pre-existing text from password entry box
        password.insert(0, result)  #Inserts generated password into entry box
    detail = Toplevel(root)

    detail.title("Add/Update Entry")
    detail.geometry("640x200")
    web = Label(detail, text="Website")  # Creating a window that contains text
    web.grid(row = 1, column=0, pady = 10)

    website = Entry(detail, width=20)  #Creates entry box
    website.grid(row = 3, column=0, padx = 50)

    user = Label(detail, text="Username")  # Creating a window that contains text
    user.grid(row = 1, column=1, pady = 10)

    username = Entry(detail, width=20) # Creates entry box
    username.grid(row = 3,column=1, padx = 50)

    passW = Label(detail, text="Password")  # Creating a window that contains text
    passW.grid(row = 1, column=2, pady = 10)

    password = Entry(detail, width=20) # Creates entry box
    password.grid(row = 3, column=2, padx = 50)
    error=Label(detail) #Creates empty label
    error.grid(row = 4, column=1)


    add = Button(detail, text = "Add", command = addition) #Creates add button
    add.grid(row = 6, column = 1, pady = 30) #Places button

    genButton = Button(detail, text = "Generate Password", command = generate) # Creates button
    genButton.grid(row = 6, column = 2, pady = 30)
    #This will be used to determine how long they want password
    spinboxValue = StringVar(value = 0) #Used to store the values of the spinbox
    spin_box = ttk.Spinbox(detail, from_= 10, to= 20, textvariable = spinboxValue, wrap = True) # Creates spinbox
    spin_box.grid(row = 5, column = 2, pady = 10)

    length = Label(detail, text = "Please determine password length: ") # Creates label with text
    length.grid(row = 5, column = 1, padx = 5)
def remove():
    cursor.execute("SELECT * FROM info") #Selects all information from info table
    for i in range(0,len(cursor.fetchall()) + 1): #Responsible for deleting all values from info database
        cursor.execute("DELETE FROM info WHERE id = ?", (i,))  # Removes all values from info database one by one
        db.commit()
        main()
def removeAll():
    def x():
        confirm.destroy() #Destroys window
    confirm = Toplevel(root) # Creates new window
    confirm.title("Confirmation") #Sets window title
    confirm.geometry("170x80") # Sets window dimensions
    txt = Label(confirm, text="Are you sure?") # Creates text label
    txt.grid(row=0, column=1)
    yes = Button(confirm, text="Yes",command = remove) # Creates button
    yes.grid(row=1, column=0, padx = 5)
    no = Button(confirm, text="No", command = x) # Creates button
    no.grid(row=1, column=2, padx= 5)

def logout():
    for i in root.winfo_children(): #For loop that destroys all windows
        i.destroy()
    loginScreen() #Launches login screen


def main():
    def removeData(input):
        cursor.execute("DELETE FROM info WHERE id = ?", (input,))  # Given an id, it removes it from database
        db.commit() # Saves it to database
        main() # Refreshes main code
    def editData(input):
        def edit():
            #This code get's the input from the entry boxes
            userData = username.get()
            passData = password.get()
            webData = website.get()
            if len(userData) != 0 and len(passData) != 0 and len(webData) != 0:  # If all have been filled
                cursor.execute("DELETE FROM info WHERE id = ?", (input,))
                insert_fields = """INSERT INTO info(website, username, password)
                VALUES(?, ?, ?)"""  # Matches corresponding info to correct table
                cursor.execute(insert_fields, (webData, userData, passData))  # Puts info into database
                db.commit()  # updates  database
                detail.destroy()  # Destroys detail window
                main()  # Calls main part of application
            else:
                error.config(text="Please enter all fields", bg='red')  # Changes empty label to display text
        def generate():
            sample_string = '19!wesdfdsfosfe3219'  # define the specific string
            # define the condition for random string
            passLength = int(spin_box.get())  # Retrieves info from spinbox
            result = ''.join(
                (random.choice(sample_string)) for x in range(passLength))  # Responsible for generating random string
            password.delete(0, 'end')  # Deletes pre-existing text from password entry box
            password.insert(0, result)  # Inserts generated password into entry box

        detail = Toplevel(root) # Creates new window
        detail.title("Add/Update Entry") # Sets title
        detail.geometry("640x200") # Sets dimensions
        web = Label(detail, text="Website")  # Creating a window that contains text
        web.grid(row=1, column=0, pady=10)

        website = Entry(detail, width=20) #Creates entry box
        website.grid(row=3, column=0, padx=50)

        user = Label(detail, text="Username")  # Creating a window that contains text
        user.grid(row=1, column=1, pady=10)

        username = Entry(detail, width=20) #Creates entry box
        username.grid(row=3, column=1, padx=50)

        passW = Label(detail, text="Password")  # Creating a window that contains text
        passW.grid(row=1, column=2, pady=10)

        password = Entry(detail, width=20) # Creates entry box
        password.grid(row=3, column=2, padx=50)

        cursor.execute("SELECT * FROM info WHERE id = ?", (input,)) # Grabs select row from info table
        info = cursor.fetchall() # Fetches the information and assigns it to variable

        website.insert(0, info[0][1]) #Inserts info into website entry box
        username.insert(0, info[0][2]) #Inserts info into username entry box
        password.insert(0, info[0][3]) #Inserts info into password entry box

        error = Label(detail)
        error.grid(row=4, column=1)

        editButton = Button(detail, text="Edit", command=edit)  # Creates edit button
        editButton.grid(row=6, column=1, pady=20)  # Places button


        gen = Button(detail, text="Generate Password", command=generate)
        gen.grid(row=6, column=2, pady=20)
        spinboxValue = StringVar(value=0)  # Used to store the values of the spinbox
        spin_box = ttk.Spinbox(detail, from_=10, to=20, textvariable=spinboxValue, wrap=True)  # Creates spinbox
        spin_box.grid(row=5, column=2, pady=20)

        length = Label(detail, text="Please determine password length: ")
        length.grid(row=5, column=1, padx=5)

    for i in root.winfo_children(): #For loop that destroys all pre-existing windows
        i.destroy()

    root.geometry("1280x720")  # Sets dimensions for window
    root.title('Password Manager') # Sets title of window


    optionsMenu = Menu(root) #Using this menu as the menu
    root.config(menu = optionsMenu) #Tells program that this is the menu to use
    optionsMenu.add_command(label = "Add [a]", command = addData) # Adds buttons/ commands into the menu

    optionsMenu.add_command(label = "Wipe", command = removeAll)

    optionsMenu.add_command(label = "Logout", command = logout)

    web = Label(root, text = "Website")   #Creates website text
    web.grid(row=0, column = 0, padx = 150)

    user = Label(root, text="Username") #Creates username text
    user.grid(row=0, column=1, padx=150)

    user = Label(root, text="Password") #Creates text
    user.grid(row=0, column=2, padx=150)

    root.bind('a', keybindDetails) # Assigns key 'a' to run a function

    cursor.execute("SELECT * FROM info") # Selects all info from table
    if(cursor.fetchall() != None): #Makes sure there is something to display
        a = 0
        cond = True
        while cond == True: #Makes this run forever as long as condition doesn't change.

            cursor.execute("SELECT * FROM info")
            info = cursor.fetchall()
            if (len(info) != 0):
                displayWeb = Label(root, text=(info[a][1]), font=("Tekton Pro", 12)) #This code displays the website entries from the database
                displayWeb.grid(column=0, row=a + 1)

                displayUser = Label(root, text=(info[a][2]), font=("Tekton Pro", 12)) #Displays the user entries
                displayUser.grid(column=1, row=a + 1)

                displayPass = Label(root, text=(info[a][3]), font=("Tekton Pro", 12)) #Displays the password entries
                displayPass.grid(column=2, row=a + 1)

                editButton = Button(root, text="Edit", command=partial(editData, info[a][0]))  # Adds button to edit, when clicked calls info function with the id of entry you want to edit
                editButton.grid(column=3, row=a + 1, pady=15, padx=15)

                deleteButton = Button(root, text="Delete", command=partial(removeData, info[a][0]))  # Adds button to delete, partial allows us to set number of arguments for a function
                deleteButton.grid(column=4, row=a + 1, pady=15)
                a+=1

            cursor.execute("SELECT * FROM info")
            if (len(cursor.fetchall()) <=a):  #Stops the while loop when all entries are displayed
                cond = False



root= Tk()

loginScreen() #calls the login screen

mainloop() #closes canvas

