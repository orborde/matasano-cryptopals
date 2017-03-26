def zero_prefix(data, size):
    return bytes(size - len(data)) + data

def zero_suffix(data, size):
    return data + bytes(size - len(data))

