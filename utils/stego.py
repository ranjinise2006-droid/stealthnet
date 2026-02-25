from PIL import Image

DELIMITER = "#####"
def encode_image(image_path, secret_message, password, output_path):
    image = Image.open(image_path)
    encoded = image.copy()

    message = password + DELIMITER + secret_message + DELIMITER
    binary_msg = ''.join(format(ord(i), '08b') for i in message)

    data_index = 0
    pixels = encoded.load()

    for y in range(encoded.height):
        for x in range(encoded.width):
            pixel = list(pixels[x, y])

            for n in range(3):
                if data_index < len(binary_msg):
                    pixel[n] = pixel[n] & ~1 | int(binary_msg[data_index])
                    data_index += 1

            pixels[x, y] = tuple(pixel)

    encoded.save(output_path)

def decode_image(image_path, password):
    image = Image.open(image_path)
    binary_data = ""
    pixels = image.load()

    for y in range(image.height):
        for x in range(image.width):
            for n in range(3):
                binary_data += str(pixels[x, y][n] & 1)

    all_bytes = [binary_data[i:i+8] for i in range(0, len(binary_data), 8)]
    decoded = ""

    for byte in all_bytes:
        decoded += chr(int(byte, 2))
        if DELIMITER in decoded:
            break

    try:
        extracted_password, message, _ = decoded.split(DELIMITER)
        if extracted_password == password:
            return message
        else:
            return "INVALID_PASSWORD"
    except:
        return "INVALID_PASSWORD"