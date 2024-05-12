import streamlit as st
from streamlit_lottie import st_lottie
from qiskit import QuantumRegister, QuantumCircuit
from qiskit_aer import AerSimulator
import random
import json 
import base64
from PIL import Image

#Generating the entangled qubits
def generate_entangled_pair(circuit, qubits):
    for i in range(0, len(qubits), 2):
        circuit.h(qubits[i])
        circuit.cx(qubits[i], qubits[i+1])
        circuit.barrier()

#Measuring Alice using the basis
def alice_measurement(basis, circuit, qubits):
    for i in range(len(qubits)):
        if basis[i] == 'x':
            circuit.h(qubits[i])
            circuit.measure(qubits[i], qubits[i])
        elif basis[i] == 'y':
            circuit.s(qubits[i])
            circuit.h(qubits[i])
            circuit.t(qubits[i])
            circuit.measure(qubits[i], qubits[i])
        elif basis[i] == 'z':
            circuit.measure(qubits[i], qubits[i])
    circuit.barrier()    
    return circuit

#Measuring Bob using the shared basis
def bob_measurement(basis, circuit, qubits):
    for i in range(len(qubits)):
        if basis[i] == 'x':
            circuit.s(qubits[i])
            circuit.h(qubits[i])
            circuit.tdg(qubits[i])
            circuit.h(qubits[i])
            circuit.measure(qubits[i], qubits[i])
        elif basis[i] == 'y':
            circuit.s(qubits[i])
            circuit.h(qubits[i])
            circuit.t(qubits[i])
            circuit.measure(qubits[i], qubits[i])
        elif basis[i] == 'z':
            circuit.measure(qubits[i], qubits[i])    
    circuit.barrier()
    return circuit

#Extracting the key
def extract_key(alice_result, bob_result):
    key = ""
    for bit_a, bit_b in zip(alice_result, bob_result):
        if bit_a == bit_b:
            key += bit_a
    return key

# Function to generate key
def generate_key():
    circuit = QuantumCircuit(4, 4)
    qubits = [i for i in range(4)]
    
    generate_entangled_pair(circuit, qubits)
    
    alice_basis = [random.choice(['x', 'y', 'z']) for i in range(4)]
    alice_measurement(alice_basis, circuit, qubits)
    
    bob_basis = [random.choice(['x', 'y', 'z']) for i in range(4)]
    bob_measurement(bob_basis, circuit, qubits)
    
    simulator = AerSimulator()
    run = simulator.run(circuit, shots = 1)
    
    result = list(run.result().get_counts().keys())[0]
    alice_result = result[:]
    bob_result = result[:]
    
    key = extract_key(alice_result, bob_result)
    return key


def load_lottiefile(filepath: str):
    with open(filepath, 'r') as f:
        return json.load(f)


# Caesar encryption method
def caesar_encryption(message, key):
    encrypted = ""
    for char in message:
        if char.isalpha():
            if char.islower():
                encrypted += chr((ord(char) - ord('a') + key) % 26 + ord('a'))
            else:
                encrypted += chr((ord(char) - ord('A') + key) % 26 + ord('A'))
        else:
            encrypted += char
            
    decrypted = ""
    for char in encrypted:
        if char.isalpha():
            if char.islower():
                decrypted += chr((ord(char) - ord('a') - key) % 26 + ord('a'))
            else:
                decrypted += chr((ord(char) - ord('A') - key) % 26 + ord('A'))
        else:
            decrypted += char
    return encrypted, decrypted


def vigenere_encrypt(plaintext, key):
    key = key.lower()
    ciphertext = ""
    key_index = 0
    for char in plaintext:
        if char.isalpha():
            shift = ord(key[key_index]) - ord('a')
            # Encrypt only alphabetic characters
            if char.islower():
                encrypted_char = chr((ord(char) - ord('a') + shift) % 26 + ord('a'))
            else:
                encrypted_char = chr((ord(char) - ord('A') + shift) % 26 + ord('A'))
            ciphertext += encrypted_char
            # Move to the next key character
            key_index = (key_index + 1) % len(key)
        else:
            # Non-alphabet characters are added as is
            ciphertext += char
            
    plaintext = ""
    key_index = 0
    for char in ciphertext:
        if char.isalpha():
            shift = ord(key[key_index]) - ord('a')
            # Decrypt only alphabetic characters
            if char.islower():
                decrypted_char = chr((ord(char) - ord('a') - shift) % 26 + ord('a'))
            else:
                decrypted_char = chr((ord(char) - ord('A') - shift) % 26 + ord('A'))
            plaintext += decrypted_char
            # Move to the next key character
            key_index = (key_index + 1) % len(key)
        else:
            # Non-alphabet characters are added as is
            plaintext += char
    return ciphertext,plaintext

    
def simple_aes_encrypt(plaintext, key):
    # Normalize key length to match plaintext block size
    block_size = len(plaintext)  # Simplification: plaintext is one block
    if len(key) < block_size:
        key = (key * (block_size // len(key) + 1))[:block_size]

    # Substitute and Permute: Simplified step
    encrypted = ""
    for char, k in zip(plaintext, key):
        # Simple substitution with key
        encrypted_char = (ord(char) + ord(k)) % 256
        encrypted += chr(encrypted_char)
        
    # Normalize key length to match ciphertext block size
    block_size = len(encrypted)
    if len(key) < block_size:
        key = (key * (block_size // len(key) + 1))[:block_size]

    # Reverse substitution
    decrypted = ""
    for char, k in zip(encrypted, key):
        decrypted_char = (ord(char) - ord(k)) % 256
        decrypted += chr(decrypted_char)


    return encrypted, decrypted
    
key = generate_key()

with st.sidebar:
    image = Image.open('logo2-removebg-preview[6].png')
    st.image(image)
    st.title("Made By: ")
    st.write('Faisal Al-Kindy')
    st.write('Fares Al-Najem')
    st.write('Feras Al-Jarbou')
    animation = load_lottiefile('animation2.json')

    st_lottie(animation, speed = 1 , loop = True , quality = 'low' )
    
st.markdown('## Information Science and Quantum Computing')

animation2 = load_lottiefile('animation.json')

st_lottie(
    animation2,
    speed = 1 ,
    loop = True ,
    quality = 'low' , 
)

st.title("QKD USING E91 PROTOCOL")

if st.button("Generate Key"):
    key = generate_key()
    st.write("Shared key:", key)
    
st.header("Enter Your Message")
message = st.text_input("Type your message here:", "")

st.header("Choose encryption method")
encryption_method = st.selectbox("Select encryption method:", ["Caesar", "vigenere", "Simple-AES"])

if encryption_method == "Caesar":
    if st.button("Encrypt"):
        if message:
            #key = generate_key()  # Generate key here
            encrypted_message, decrypted_message = caesar_encryption(message, int(key, 2))
            st.markdown("### Encrypted message:")
            st.text_area(label="", value=encrypted_message, height = 10, key="Cencrypted_message_text_area")
            st.markdown("### Decrypted message:")
            st.text_area(label="", value=decrypted_message , height = 10, key="Cdecrypted_message_text_area")
            
if encryption_method == "vigenere":
    if st.button("Encrypt"):
        if message:
            #key = generate_key()  # Generate key here
            encrypted_message, decrypted_message = vigenere_encrypt(message, key)
            st.markdown("### Encrypted message:")
            st.text_area(label="", value=encrypted_message, height = 10, key="Vencrypted_message_text_area")
            st.markdown("### Decrypted message:")
            st.text_area(label="", value=decrypted_message , height = 10, key="Vdecrypted_message_text_area")
            
if encryption_method == "Simple-AES":
    if st.button("Encrypt"):
        if message:
            #key = generate_key()  # Generate key here
            encrypted_message, decrypted_message = simple_aes_encrypt(message, key)
            encrypted_base64 = base64.b64encode(encrypted_message.encode()).decode() 
            st.markdown("### Encrypted message:")
            st.text_area(label="", value=encrypted_base64, height = 10, key="AESencrypted_message_text_area")
            st.markdown("### Decrypted message:")
            st.text_area(label="", value= message, height = 10, key="AESdecrypted_message_text_area")
