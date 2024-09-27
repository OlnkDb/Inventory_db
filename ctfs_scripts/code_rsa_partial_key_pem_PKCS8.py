import base64
import re
import argparse

def process_file(filename):
    """Read the entire content of the file."""
    with open(filename, "r") as f:
        file_content = f.read()
    return file_content

def extract_base64_data(pem_data):
    """Extract base64-encoded data from PEM formatted string."""
    base64_data = re.sub(r'-----BEGIN [A-Z ]+-----', '', pem_data)
    base64_data = re.sub(r'-----END [A-Z ]+-----', '', base64_data)
    base64_data = base64_data.strip().replace('\n', '')
    ## CTF UTILITY 
    base64_data = base64_data.replace('*', 'A')
    return base64_data

def read_pem_file(pem_data):
    """Decode base64-encoded data to get DER encoded bytes."""
    der_data = base64.b64decode(pem_data, validate=False)
    return der_data

def read_tag(data, index):
    """Read the ASN.1 tag from the data at the given index."""
    if index >= len(data):
        raise ValueError("Unexpected end of data while reading tag.")
    tag = data[index]
    index += 1
    return tag, index

def read_length(data, index):
    """Read the ASN.1 length from the data at the given index."""
    if index >= len(data):
        raise ValueError("Unexpected end of data while reading length.")
    first_byte = data[index]
    index += 1
    if first_byte < 0x80:
        length = first_byte
    else:
        num_bytes = first_byte & 0x7F
        if num_bytes == 0:
            raise ValueError("Indefinite lengths are not supported in DER encoding.")
        if index + num_bytes > len(data):
            raise ValueError("Length bytes exceed available data.")
        length_bytes = data[index:index+num_bytes]
        index += num_bytes
        length = int.from_bytes(length_bytes, byteorder='big')
    return length, index

def read_value(data, index, length):
    """Read a value of the specified length from the data at the given index."""
    if index + length > len(data):
        raise ValueError("Value exceeds available data.")
    value = data[index:index+length]
    index += length
    return value, index

def parse_asn1(data, index, max_index, indent=0):
    """Recursively parse ASN.1 structures."""
    while index < max_index:
        try:
            tag, index = read_tag(data, index)
            print("    " * indent + f"Tag: {tag:#0x} at index {index - 1}")
            length, index = read_length(data, index)
            if tag == 0x30:  # SEQUENCE
                print("    " * indent + "Entering SEQUENCE")
                print("    " * indent + f"Length: {length} bytes")
                seq_end = index + length
                index = parse_asn1(data, index, seq_end, indent + 1)
                print("    " * indent + "Exiting SEQUENCE")
            elif tag == 0x02:  # INTEGER
                print("    " * indent + f"Length: {length} bytes")
                value_bytes, index = read_value(data, index, length)
                value_int = int.from_bytes(value_bytes, byteorder='big', signed=False)
                print("    " * indent + f"INTEGER value: {value_int}")
            else:
                # Skip over unhandled tags by reading their length and value
                print("    " * indent + f"Unhandled tag: {tag:#0x}, skipping value.")
                # Read the length and skip the value
                length, index = read_length(data, index)
                index += length
        except (ValueError, IndexError) as e:
            print("    " * indent + f"Error parsing ASN.1 structure: {e}")
            break  # Exit the loop if there's an error
    return index

def rsa_ansi_der(data):
    """Parse the RSA private key in ASN.1 DER format."""
    index = 0
    tag, index = read_tag(data, index)
    if tag != 0x30:
        raise ValueError("Expected SEQUENCE tag (0x30) at the start.")
    length, index = read_length(data, index)
    max_index = index + length
    print("Starting ASN.1 parsing of RSA private key.")
    parse_asn1(data, index, max_index)
    print("Finished ASN.1 parsing.")

# Use argparse to accept filename from command line
parser = argparse.ArgumentParser(description="Parse ASN.1 DER encoding of a PEM file.")
parser.add_argument("filename", help="The file to process")
args = parser.parse_args()

# Process the provided file
data = process_file(args.filename)
data = extract_base64_data(data)
data = read_pem_file(data)

# Parse and display the ASN.1 structure
rsa_ansi_der(data)
