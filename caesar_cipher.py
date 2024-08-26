def caesar_encrypt(text, shift):
    encrypted_text = ""
    for char in text:
        if char.isalpha():
            shift_amount = shift % 26
            code_point = ord(char) + shift_amount
            if char.islower():
                if code_point > ord('z'):
                    code_point -= 26
            elif code_point > ord('Z'):
                code_point -= 26
            encrypted_text += chr(code_point)
        else:
            encrypted_text += char
    return encrypted_text

def caesar_decrypt(text, shift):
    return caesar_encrypt(text, -shift)

