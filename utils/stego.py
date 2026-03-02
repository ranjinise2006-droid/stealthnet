from PIL import Image

def encode_image(image_path, secret_message, password, output_path):
    image = Image.open(image_path).convert("RGB")
    encoded = image.copy()

    message = secret_message.strip()
    binary_msg = ''.join(format(ord(i), '08b') for i in message)
    msg_length = format(len(binary_msg), '032b')
    binary_msg = msg_length + binary_msg

    data_index = 0
    pixels = encoded.load()
    max_capacity = encoded.width * encoded.height * 3

    if len(binary_msg) > max_capacity:
        raise ValueError("Message too large for this image")

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
    image = Image.open(image_path).convert("RGB")
    binary_data = ""
    pixels = image.load()

    # Read first 32 bits as payload length
    count = 0
    for y in range(image.height):
        for x in range(image.width):
            for n in range(3):
                binary_data += str(pixels[x, y][n] & 1)
                count += 1
                if count == 32:
                    break
            if count == 32:
                break
        if count == 32:
            break

    if len(binary_data) < 32:
        return "INVALID_PASSWORD"

    message_length = int(binary_data, 2)
    data_bits = []
    count = 0
    total_bits_read = 0

    for y in range(image.height):
        for x in range(image.width):
            for n in range(3):
                if total_bits_read >= 32:
                    if count < message_length:
                        data_bits.append(str(pixels[x, y][n] & 1))
                        count += 1
                    else:
                        break
                total_bits_read += 1
            if count >= message_length:
                break
        if count >= message_length:
            break

    if count < message_length:
        return "INVALID_PASSWORD"

    binary_payload = ''.join(data_bits)
    all_bytes = [binary_payload[i:i+8] for i in range(0, len(binary_payload), 8)]
    return ''.join(chr(int(byte, 2)) for byte in all_bytes if len(byte) == 8)
