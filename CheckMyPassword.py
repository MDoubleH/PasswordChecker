#Summer 2021 Password Checker Project

# https://haveibeenpwned.com/Passwords
# https://pypi.org/project/requests/
# https://passwordsgenerator.net/sha1-hash-generator/

# password123 - SHA1 - CBFDAC6008F9CAB4083784CBD1874F76618D2A97
# API accept 5 first hex-symbols from SHA1 and returns the rest 35 hex symbols with the hacked hashes

'''Provides API with the first 5 symbols of SHA1 hash of the passoword 
    and get response with the 35-long tail of the hacked hashes'''
def request_api_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f'Error fetching: {res.status_code}, check the API and try again')
    return res

def get_password_leaks_count(hashes, hash_tail_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines()
    )
    for hash, count in hashes:
        if hash == hash_tail_to_check:
            return count
    return 0

#Check if password exists in API response
def pwned_api_check(password):
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_char, tail = sha1password[:5], sha1password[5:]
    response = request_api_data(first5_char)
    return get_password_leaks_count(response, tail)


def main(args):
    for password in args:
        count=pwned_api_check(password)
        if count:
            print (f'{password} was found {count} times ... Change this password')
        else:
            print (f'{password} was NOT found in breached passwords')
    return 'done'

if __name__ == '__main__':
    main(sys.argv[1:])
    

'''
The API takes the first 5 characters of the 'SHA 1 hash'.
Therefore, we generate a SHA 1 hash of our password, then pass the first five characters of that hash.
This makes use of K-anonymity so that no one can backtrace our actual password using our hash.
This website list all the hashes starting with the 5 characters we have passed,
We can then manually check whether our password has been pwned or not
'''
