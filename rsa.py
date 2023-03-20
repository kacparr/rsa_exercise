import random
import time
start = time.time()
def big_power(num, power, mod = False):
    print('BIG POWER')
    arr = []
    tescik = 0
    res = 1
    placeholder = num
    while power > 0: #convertion to binary
        arr.append(power % 2)
        power //= 2
    print(f'reversed: {arr[::-1]} arr length: {len(arr)} num: {num}')
    for i in range(len(arr)):
        print(f'i:{i} arr[i]:{arr[i]} potega:{2**(i)} wynik: {arr[i]*2**(i)}') #test if everything works correctly
        tescik += arr[i]*2**(i)
        var = num
        num **= 2 #inaczej pomnoz num z OG num do potegi 2 do potegi i (placeholder^[2^i])
        if arr[i] == 1:
                res *= var
                res = res % mod if mod else res
            # print(f'    res: {res}, num: {num}, ognum = {placeholder} placeholder: {placeholder **(2**i)}')
        else:
            # print(f'    res: {res}, num: {num}, placeholder: {placeholder **(2**i)}')
            continue
    # print(f'    res: {res}, tescik:{tescik}, placeholder: {placeholder}, arr: {arr}')
    return res 

def find_prime(number):
    print('FIND PRIME')
    accuracy = 3 # liczba iteracji funkcji
    s = 0 # liczba największej potęgi dwójki którą można podzielić liczbę
    d = number - 1 #liczba która będzie pasować do formuły: number = 1 + 2^s *d, inaczej d = number + 1/2^s
    szukana = d
    while d % 2 == 0:
        s +=1
        d //= 2 
    print(f'    1. random: {number}, d: {d}, s: {s}')

    for i in range(accuracy):
        base = random.randint(2, szukana) #losowa liczba range 2, szukana
        print(f'    próba {i+1} base: {base}: d: {d}')
        x = big_power(base, d, number) #wzor na x
        print(f'        1. x: {x}, szukana: {szukana}')

        if x == 1:
            print('     x jest równa 1')
            i -= 1
            continue
        elif s == 1 and x != szukana:
            print(f'    {number} nie jest liczba pierwsza - fail za 1 razem')
            return False

        r = 1
        while r < s and x != szukana:
            x = big_power(x, 2, number) #dodawanie potegi dwojki do x az do konca liczby s
            print(f'    {r+1}. x: {x}, szukana: {number -1}')
            r+=1
            continue
        if x != szukana:
            print(f'    liczba {number} nie jest pierwsza - r w pętli')
            return False
        
        print(f'    test {i+1}: udany')
        continue
    return number

def make_prime_pair():
    arr = []
    while len(arr) != 2:
        # randarray = [(random.randint(1000,5000) *2) -1, 2]
        # randomnum = big_power(randarray[0],randarray[1])
        randomnum = random.randint(1000,5000)  
        randomnum = (randomnum * 2) - 1 #nieparzysta liczba 
        if find_prime(randomnum) != False:
             arr.append(randomnum)
    return arr

prime_pair = make_prime_pair()

def gcd(a, b):
    while b != 0:
        c = b
        b = a % b
        a = c
    return a
        

def reversed_modulo(a, b):
    print('REVERSED MODULO')
    # 1. NWD(a, b) musi byc rowne NWD(w, z), 2: tożsamość bezouta to a*c + b*d = NWD(a, b)
    # 3. wzory na w i z: (a*u + b*v = w), (a*x + b*y = z)
    # 4. zeby NWD(a,b) i NWD(w,z) byly ze soba rowne to w = a i b = z
    # 5. zeby punkt 4 był prawdziwy to: (u,v = 1,0),(x,y = 0,1)
    w, z = a, b 
    u, x = 1,0 # liczba c dla w i z, liczby v i y nie sa potrzebne
    i = 1
    while w != 0:
        print(f'    proba {i}:')
        print(f'    before: u, x {u, x}, w, z: {w, z}')
        if w < z: # make int division possible
            u, x = x, u 
            # x1 = x
            # x = u
            # u = x1
            w, z = z, w
        q = w // z 
        u, w = u - (q * x), w - (q * z) #in other words w = w mod z, this is literally GCD
        print(f'    after: u, x: {u, x}, w, z: {w, z}, q: {q}')
        i += 1
    if z != 1:
        return None
    elif x < 0:
        x += b
    return x

def make_rsakeys(numbers):
    print('RSA KEYS')
    p, q = numbers[0], numbers[1]
    phi = (p - 1) * (q - 1) 
    n = p*q
    print(f'    p: {p}, q: {q}, phi: {phi}, n: {n}')
    p, q = None, None

    e = 3 #wykladnik publiczny - najmniejsza liczba wzglednie pierwsza z phi
    while True:
        if gcd(e, phi) == 1:
            break
        e += 2
    e = 17
    d = reversed_modulo(e, phi) #wykładnik prywatny - reversed modulo

    return ((e,n), (d,n))

def encrypt_message(message, public_key):
    e,n = public_key[0], public_key[1]
    encrypted = 0
    if message < 0 or message > n:
        return "message too big!"
    print(f'encrypt args for big power: {message, e, n}')
    encrypted = big_power(message , e, n)
    return encrypted


def decrypt_message(message, private_key):
    d,n = private_key[0], private_key[1]
    if message < 0 or message > n:
        return "message too big!"
    print(f'decryped args for big power: {message, d, n}')
    decrypted = big_power(message,d, n) 
    return decrypted

public_keys = make_rsakeys(prime_pair)
public, private = public_keys[0], public_keys[1]
print(f'RESULTS\n   public key: {public}, private key: {private}')

message = 123
en = encrypt_message(message, public)
de = decrypt_message(en, private)
print(f'    message: {message}, encrypted: {en}, decrypted: {de}')
print(f'time:{time.time() - start}s')
#### TO DO: ###
# poprawa big_power (rekursja?) zeby nie byl tak powolny
# 
### FUTURE PLANS: ###
# optymalizacja programu 
# poprawna funkcja random
# padding
# signatures
# ogarnac jak mozna zaszyfrowac wiadomosc w ascii (potencjalnie tez pliki)
# konwersja kluczy na hex
# jakies gui maybe
# async
#
### DONE: ###
# klucz prywatny (rozszerzony euklides i odwrotność modulo)
# naprawic big number bo nie zawsze dziala poprawnie xDDDD daje za duze potegi
# dekrypcja wiadomości
#