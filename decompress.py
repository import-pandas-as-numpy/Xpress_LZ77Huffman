# This file is Copyright 2022 Forensicxlab and under the GNU GPLv3 license
import io, numpy

def encoded_bit_length(data, symbol):
    if (symbol % 2) == 0:
        return int(data[symbol//2] & 0x0f)
    else:
        return int(data[symbol//2] >> 4)

def Read16Bits(input, current_position):
    if current_position > len(input):
        print("Incomplete Prefetch")
        exit(1)
    stream = io.BytesIO(input)
    stream.seek(current_position)
    byte_value = bytearray(stream.read(2))
    val = numpy.uint16(0)
    j = 0
    for i in byte_value:
        val = val | (numpy.uint16(i) << numpy.uint(j*8))
        j = j+1
    return val

def ReadByte(input, current_position):
    stream = io.BytesIO(input)
    stream.seek(current_position)
    return int.from_bytes(stream.read(1),"little")

def lz77_huffman_decompress(in_buf):
    """
    Description : Decompress the prefetch using LZ77+Huffman Decompression Algorithm
    Params :
        @data : The compressed prefetch data extracted from memory
        @result : The uncompressed prefetch file ready to be forensically analysed
    Possible errors :
        Invalid compressed data.
    """
    if len(in_buf) < 256:
        print("Error : The prefetch must use a 256-byte Huffman table. -> Invalid data")

    #First, we construct our Huffman decoding table
    decoding_table = [0] * (2**15)
    current_table_entry = 0
    encoded_data = in_buf[0:256]
    for bit_length in range(1,15):
        for symbol in range(0, 511):
            if encoded_bit_length(encoded_data, symbol) == bit_length: # If the encoded bit length of symbol equals bit_length
                entry_count = (1 << (15 - bit_length))
                for i in range(0, entry_count):
                    if current_table_entry >= 2**15: #Huffman table length
                        raise ValueError('CorruptedData')
                    decoding_table[current_table_entry] = numpy.uint16(symbol)
                    current_table_entry += 1
    if current_table_entry != 2**15:
        raise ValueError('CorruptedData')


    #Then, it's time to decompress the data
    """
    The compression stream is designed to be read in (mostly) 16-bit chunks, with a 32-bit register
    maintaining at least the next 16 bits of input. This strategy allows the code to seamlessly handle the
    bytes for long match lengths, which would otherwise be awkward.
    """
    out_buf = []
    input_buffer = in_buf
    current_position = 256 # start at the end of the Huffman table
    next_bits = Read16Bits(input_buffer, current_position)
    current_position += 2
    next_bits = numpy.uint32(next_bits) <<  numpy.int64(16)
    next_bits = next_bits | numpy.uint32(Read16Bits(input_buffer, current_position))
    current_position += 2
    extra_bit_count = 16
    # Loop until a block terminating condition
    while True:
        next_15_bits = numpy.uint32(next_bits) >> numpy.uint32((32 - 15))
        huffman_symbol = decoding_table[next_15_bits]
        huffman_symbol_bit_length = encoded_bit_length(encoded_data, huffman_symbol)
        next_bits = numpy.int32(next_bits << huffman_symbol_bit_length)
        extra_bit_count -= huffman_symbol_bit_length
        if extra_bit_count < 0:
            next_bits = next_bits | (numpy.uint32(Read16Bits(input_buffer, current_position)) << (-extra_bit_count))
            current_position += 2
            extra_bit_count += 16
        if huffman_symbol < 256:
            out_buf.append(huffman_symbol)
        elif huffman_symbol == 256 and (len(input_buffer) - current_position) == 0:
            print("Decompression is complete")
            return out_buf
        else:
            huffman_symbol = huffman_symbol - 256
            match_length = huffman_symbol % 16
            match_offset_bit_length = huffman_symbol // 16
            if match_length == 15:
                match_length = numpy.uint16(ReadByte(input_buffer, current_position))
                current_position+=1
                if match_length == 255:
                    match_length = Read16Bits(input_buffer, current_position)
                    current_position += 2
                    if match_length < 15:
                        raise ValueError('CorruptedData')
                    match_length -= 15
                match_length += 15
            match_length += 3
            match_offset = next_bits >> (32 - match_offset_bit_length)
            match_offset += (1 << match_offset_bit_length)
            next_bits = next_bits << match_offset_bit_length
            extra_bit_count -= match_offset_bit_length
            if extra_bit_count < 0:
                next_bits = next_bits | (numpy.uint32(Read16Bits(input_buffer, current_position)) << (-extra_bit_count))
                current_position += 2
                extra_bit_count += 16
            for _ in range(0, match_length):
                to_write = out_buf[len(out_buf) - int(match_offset)]
                out_buf.append(to_write)


with open("ATOM.EXE-3A9166E2.pf","rb") as stream:
    stream.seek(0x0004)
    decompressed_size = int.from_bytes(stream.read(4),"little")
    stream.seek(0x0008)
    compressed_bytes = stream.read()
out = lz77_huffman_decompress(bytearray(compressed_bytes))
