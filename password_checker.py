import requests
import hashlib
import sys

def request_api_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f'Error fetching: {res.status_code}, check the API and try again')
    return res

def get_password_leaks_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0

def pwned_api_check(password):
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_char, tail = sha1password[:5], sha1password[5:]
    response = request_api_data(first5_char)
    return get_password_leaks_count(response, tail)

def main(passwords):
    for password in passwords:
        count = pwned_api_check(password)
        if count:
            print(f'{password} Esta senha já foi vista {count} vezes, apareceu em uma violação de dados e nunca deve ser usada. Se você já usou em algum lugar antes, mude!')
        else:
            print(f'{password} Boas notícias, esta senha não foi encontrada em nenhuma das senhas Pwned!')

if __name__ == '__main__':
    # Solicitação de entrada de senhas do usuário
    passwords = input("Digite as senhas separadas por espaço: ").split()

    main(passwords)