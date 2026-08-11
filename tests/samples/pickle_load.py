import pickle

data = b"\x80\x03]q\x00(X\x04\x00\x00\x00testq\x01e."
obj = pickle.loads(data)
print(obj)
