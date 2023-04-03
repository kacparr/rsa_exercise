import random
import time
import os
import Crypto
import hashlib
start = time.time()
def big_power(num, power, mod = False) -> int:
    # print('BIG POWER')
    arr = []
    res = 1
    while power > 0: #convertion to binary
        arr.append(power % 2)
        power //= 2
    for i in range(len(arr)):
        var = num
        num *= num % mod if mod else num
        if arr[i] == 1:
                res *= var
                res = res % mod if mod else res
        else:
            continue
    return res 

def find_prime(number):
    print('FIND PRIME')
    accuracy = 10
    s = 0 # liczba największej potęgi dwójki którą można podzielić liczbę
    d = number - 1 #liczba która będzie pasować do formuły: number = 1 + 2^s *d, inaczej d = number + 1/2^s
    szukana = d
    while d % 2 == 0:
        s +=1
        d //= 2 
    print(f'    1. random: {number}, d: {d}, s: {s}')

    for i in range(accuracy):
        base = random.randint(2, szukana) 
        print(f'    próba {i+1} base: {base}: d: {d}')
        x = big_power(base, d, number)
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

def make_prime_pair() -> list:
    arr = []
    while len(arr) != 2:
        randomnum = 2 *(random.getrandbits(256) //2) +1
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

def make_rsakeys(numbers: list) -> tuple:
    print('RSA KEYS')
    p, q = numbers[0], numbers[1]
    phi = (p - 1) * (q - 1) 
    n = p*q
    print(f'    p: {p}, q: {q}, phi: {phi}, n: {n}')
    p, q = None, None

    e = 3 
    while True:
        if gcd(e, phi) == 1:
            break
        e += 2
    d = reversed_modulo(e, phi) 

    return ((e,n), (d,n))

def i2osp(x: int, lenx) -> bytes:
    return int.to_bytes(x, length=lenx, byteorder="big")
 
def os2ip(x: bytes) -> int:
    return int.from_bytes(bytes=x, byteorder="big")

def mgf1(seed: bytes, length: int, h_func = hashlib.sha1) -> bytes: # create hashed mask for oaep 
    #apply a hash funtion to (seed + iterated length - 1) and return the result[:length]
    h_len = h_func().digest_size 
    if length > h_len << 32: 
        return 'mask too long!'
    t = b""
    for counter in range(length - 1):
        c = i2osp(counter, 4)
        t += h_func(seed + c).digest()
    return t[:length]

def xor(key: bytes, byte: bytes) -> bytes:
    res = bytes([a ^ b for a,b in zip(key,byte)]) #make xor operation when byte and key are full 
    if len(byte) > len(key):
        for i in range(len(key), len(byte)):
            res += (byte[i].to_bytes(1, byteorder='big')) #concatenate remaining bits when byte is bigger (1,0 = 1)
    return (res)

def oaep_encryption(message: bytes, n: int, label: str = "", h_func = hashlib.sha1) -> bytes:
    k = n.bit_length() // 8 # length of rsa n in bytes
    label = label.encode('utf-8')
    l_hash = h_func(label).digest()
    m_len = len(message)
    h_len = h_func().digest_size 
    if m_len > (k - 2 * h_len - 2):
        return ("message too big oaep!", (k - 2 * h_len - 2), m_len, h_len, k)
    padding_string = b'\x00' * (k - m_len - 2 * h_len - 2) 
    data_block = l_hash + padding_string + b'\x01' + message
    if len(data_block) > (k - h_len - 1):
        return "data block too big!"
    seed = os.urandom(h_len)

    db_mask = mgf1(seed= seed, length= k-h_len - 1) #mask for data block from seed with data block length
    masked_db = xor(db_mask, data_block)

    seed_mask = mgf1(masked_db, h_len) #mask for seed from seed_mask with seed length
    masked_seed = xor(seed, seed_mask)
    em = b'\x00' + masked_seed + masked_db
    print(f"OAEP ENCRYPTION\nem:{em}\nhlen:{h_len}\nmasked seed: {masked_seed}\nmasked db:{masked_db}\ndb mask: {db_mask}\nseed_mask: {seed_mask}\nseed: {seed}\ndb: {data_block}\npadding_string:{padding_string}\nmessage:{message}")
    return em

def oaep_decryption(em: bytes, n: int, label: str = "", h_func = hashlib.sha1) -> bytes:
    k = n.bit_length() // 8
    label = label.encode('utf-8')
    l_hash = h_func(label).digest()
    h_len = h_func().digest_size
    masked_seed, masked_db = em[1:h_len+1], em[h_len+1:] #masked seed has length of h_len
    #1) having masked_db make seed_mask that allows to find seed: mgf1(masked_seed, seed_mask)
    #2) having seed make db_mask that allows to find db: mgf1(masked_db, db_mask)
    seed_mask = mgf1(masked_db, h_len) 
    seed = xor(seed_mask, masked_seed)
    db_mask = mgf1(seed, k - h_len - 1)
    data_block = xor(db_mask, masked_db)
    #3) split data_block into parts and check if they are valid
    l_hash_prim = data_block[:h_len]
    controlbyte = data_block.find(b'\x01',h_len) #find byte 0x01 between padding string and message
    padding_string = data_block[h_len:controlbyte]
    message = data_block[controlbyte+1:]

    rules = [i2osp(em[0],1) == b'\x00', #rules to check
            l_hash_prim == l_hash, 
            padding_string == (b'\x00' * len(padding_string)), 
            data_block[controlbyte] == 1]
    print(rules, em[0])
    print(f"OAEP DECRYPTION\nem:{em}\nhlen:{h_len}\nmasked seed: {masked_seed}\nmasked db:{masked_db}\ndb mask: {db_mask}\nseed_mask: {seed_mask}\ndecrypted seed: {seed}\ndecrypted db: {data_block}\npadding string:{padding_string}\nmessage:{message}\nem[0:2]:{[i2osp(em[i], 3) for i in range(3)]}")
    if all(rules):
        return message
    else:
        return ("Error! conditions are not met!", (i2osp(em[0],1), b'\x00') (l_hash_prim, l_hash), (padding_string, b'\x00' * len(padding_string)), (data_block[controlbyte], 1), h_len)
    

def encryption(message, key):
    e, n = key[0], key[1]
    if message < 0 or message > n:
        return ("message too big en!", message.bit_length(), n.bit_length())
    result = big_power(message, e, n)
    return result

def decryption(message, key):
    d, n = key[0], key[1]
    if message < 0 or message > n:
        return ("message too big!", len(message), n)
    result = big_power(message, d, n)
    return result

def byte_encryption(message, key):
    d, n = key[0], key[1]
    len_n = n.bit_length() // 8
    encrypted = encryption(os2ip(message), key)
    return i2osp(encrypted, len_n)

def byte_decryption(message, key):
    d, n = key[0], key[1]
    len_n = n.bit_length() // 8
    decrypted = decryption(os2ip(message), key)
    return i2osp(decrypted, len_n)

def encrypt_oeap(message, key):
    d, n = key[0], key[1]
    h_len = hashlib.sha1().digest_size
    len_n = n.bit_length() // 8
    if len(message) >= len_n - h_len - 2:
        return ("Message too big ENCRYPTOAEP!!", len_n - h_len - 2, h_len, len_n)
    return byte_encryption(oaep_encryption(message,n),key)

def decrypt_oeap(message, key):
    d, n = key[0], key[1]
    h_len = hashlib.sha1().digest_size
    len_n = n.bit_length() // 8
    if len_n != len(message):
        return ("Message too big DECRYPTOAEP!!", len_n, len(message)) 
    return oaep_decryption(byte_decryption(message,key),n)

keys = make_rsakeys(make_prime_pair())
public, private = keys[0], keys[1]
print(f'RESULTS\n   public key: {public}, private key: {private}')

test_message = "siemaziomus...."
test_message = test_message.encode('utf-8')

oaepencrypted = encrypt_oeap(test_message,public)
oaepdecrypted = decrypt_oeap(oaepencrypted,private)
print(test_message.decode(), oaepencrypted, oaepdecrypted.decode())

#### TO DO: ###
# poprawna funkcja random (nie pythonowa)
# optymalizacja programu 
# optymalizacja szukania liczb pierwszych(512 bitowa liczba sie dlawi) 
# naprawa OAEP bo nie działa 
# 
### FUTURE PLANS: ###
# signatures
# konwersja kluczy na hex
# jakies gui maybe
# async
# aes
### DONE: ###
# oaep
# klucz prywatny (rozszerzony euklides i odwrotność modulo)
# naprawic big number bo nie zawsze dziala poprawnie xDDDD daje za duze potegi
# dekrypcja wiadomości
# poprawa big_power zeby nie byl tak powolny
#