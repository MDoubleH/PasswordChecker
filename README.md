# PasswordChecker
This API uses SHA1 Hashing, so I must also use SHA1 Hashing on my passwords and use that hashed output of my passwords, to check whether my password has been pwned or not. 
However, since a password can easily be revealed by reversing the hash, 
the API uses a technique called K-anonymity which allows somebody to receive info about us, yet still not know who we are. 
This API makes use of K-anonymity by us only taking in the first five characters of our hashed password. 
The API will proceed to compare the hash of the first five characters of our password against its database of leaked passwords, 
we will then receive a list of all the passwords that match, allowing us to be able to check the rest of the hash function to see if our password has ever been pwned!
