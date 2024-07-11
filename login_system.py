import hashlib
from pickle import TRUE # the hashlib library to use hashing functions

# functhion to hash a password with SHA256 functhion
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# function to verify if the stored hashed password matches the provided password after hashing
def verify(stored , provid):
    return stored == hash_password(provid)

# dictionary to store the usernames and thier hashed password
users = {}
# loop to prompt user to login or register
while (True):
    action = input('Do you want to [register] or [login] ').strip().lower() # Prompt the user for an action (register or login)
    if (action == "register"): 
        username = input('enter the username: ').strip().lower()# Prompt the user for a username
        if username in users: # check if the username is already exists
            print('the username is already exists. Try another one.')
            continue # if the username exists, prompt for a different username
        password = input('enter your password').strip()# prompt the user for a password
        hashed_password = hash_password(password) # hash the password using the hash_password function
        users[username]=hashed_password # store the username and hashed password in the dictionary
        print(f'user {username} registered successfully!')
    elif (action == "login"):
        username = input('enter your username: ').strip()
        password = input('enter your password: ').strip()
        stored_password = users.get(username) # retrieve the stored hashed password for the given username
        # verify if the provided password, when hashed, matches the stored hashed password
        if stored_password and  verify(stored_password , password):
            print(f'welcome back {username}')
        else:
            print('invalid username or password.')
    else:
        print("Invalid action. Please choose 'register' or 'login'.")# if the action is not valid, prompt the user again