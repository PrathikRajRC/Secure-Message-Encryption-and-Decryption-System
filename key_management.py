def save_key(key, filename):
    with open(filename, 'wb') as file:
        file.write(key)

def load_key(filename):
    try:
        with open(filename, 'rb') as file:
            return file.read()
    except FileNotFoundError:
        return None

