import argparse
import os.path
import sys

def main(input, output):

    if not os.path.isfile(input):
        print(f"[-] Failed to open: {input}")
        sys.exit(0)

    h_in = open(input, "rb")
    h_out = open(output, "wb")

    bytes_in = bytearray(h_in.read())
    bytes_in_len = len(bytes_in)

    print(f"[*] Read: {str(bytes_in_len)} bytes")
    print("[*] Now deobfuscating, this might take a while")
    
    chunks = [bytes_in[i:i+1000000] for i in range(0, len(bytes_in), 1000000)]
    for chunk in chunks:
        for i in range(0, len(chunk)):
            chunk[i] ^= 0x41

        h_out.write(bytes(chunk))

    print(f"[*] Deobfuscated to: {output}")

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="")
    parser.add_argument("-input", required=True)
    parser.add_argument("-output", required=True)

    args = parser.parse_args()
    main(args.input, args.output)
