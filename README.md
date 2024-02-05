
Esse programa em Python verifica se uma senha fornecida pelo usuário já foi comprometida em violações de dados. Ele utiliza a API do serviço "Have I Been Pwned" (https://haveibeenpwned.com/) para obter informações sobre senhas comprometidas.

Aqui está uma descrição detalhada do que cada parte do programa faz:

Importação de bibliotecas:

import requests
import hashlib


requests: Biblioteca para fazer requisições HTTP.
hashlib: Biblioteca para cálculos de hash (neste caso, para calcular o hash SHA-1 da senha).


Função request_api_data:
def request_api_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f'Error fetching: {res.status_code}, check the API and try again')
    return res
    
Constrói a URL da API HIBP para obter hashes de senhas com base nos primeiros cinco caracteres do hash SHA-1 da senha.
Faz uma solicitação GET à API e retorna a resposta.
Se o status da resposta não for 200 (OK), lança uma exceção.

Função get_password_leaks_count:
def get_password_leaks_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0
Analisa a resposta da API que contém informações sobre senhas comprometidas.
Divide as linhas da resposta em pares de hash e contagem.
Itera pelos pares e retorna a contagem de vazamentos para a senha específica, se encontrada.

Função pwned_api_check:
def pwned_api_check(password):
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_char, tail = sha1password[:5], sha1password[5:]
    response = request_api_data(first5_char)
    return get_password_leaks_count(response, tail)
Calcula o hash SHA-1 da senha e divide-o em duas partes: os primeiros cinco caracteres (first5_char) e o restante (tail).
Chama a função request_api_data para obter informações da API.
Utiliza a função get_password_leaks_count para obter a contagem de vazamentos para a senha.


Função main:
def main(passwords):
    for password in passwords:
        count = pwned_api_check(password)
        if count:
            print(f'{password} Esta senha já foi vista {count} vezes, apareceu em uma violação de dados e nunca deve ser usada. Se você já usou em algum lugar antes, mude!')
        else:
            print(f'{password} Boas notícias, esta senha não foi encontrada em nenhuma das senhas Pwned!')
Itera sobre as senhas fornecidas pelo usuário.
Para cada senha, chama pwned_api_check para verificar se a senha foi comprometida.
Exibe uma mensagem indicando se a senha foi comprometida ou não.

passwords = input("Digite as senhas separadas por espaço: ").split()
main(passwords)
Solicita ao usuário que insira senhas separadas por espaço.
Chama a função main para realizar a verificação das senhas.
