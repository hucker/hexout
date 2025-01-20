import pytest
import math
from hexout import HexOut

@pytest.fixture
def byte_data():
    return b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16'

@pytest.fixture
def short_byte_data():
    return b'\x00\x01\x02\x03\x04\x05\x06\x07'



@pytest.mark.parametrize("byte_data,expected", [
    (b'\x00\x01\x02\x03', "00 01 02 03"),
    (b'\x0F\xAF\xB0\x1F\x2F', "0F AF B0 1F 2F"),
    (b'\xFF', "FF"),
    (b'\x00\x00\x00\x00\x00\x01', "00 00 00 00 00 01"),
    (b'\x00\x10\x20\x30\x40\x50\x60\x70\x80\x90\xA0\xB0\xC0\xD0\xE0\xF0',
     "00 10 20 30 40 50 60 70 80 90 A0 B0 C0 D0 E0 F0")
])
def test_hexout_single_line(byte_data, expected):
    # Initialize HexOut with columns=0
    ho = HexOut()

    # Call and test
    assert ho.as_hex(byte_data) == expected

@pytest.mark.parametrize("byte_data, columns, expected", [
    (b'\x00\x01\x02\x03\x04', 4, "00 01 02 03\n04"),
    (b'\x00\x01\x02\x03\x04\x05', 4, "00 01 02 03\n04 05"),
    (b'\x00\x01\x02\x03\x04\x05\x06', 4, "00 01 02 03\n04 05 06"),
    (b'\x00\x01\x02\x03\x04\x05\x06\x07', 4, "00 01 02 03\n04 05 06 07")
])
def test_hexout_multi_line(byte_data, columns, expected):
    ho = HexOut(columns=columns)
    assert ho.as_hex(byte_data) == expected


@pytest.mark.parametrize("byte_data, hex_format, expected", [
    (b'\x01\x02\x03\x04', "{}", "1 2 3 4"),  # Without leading zeros
    (b'\xA1\xB2\xC3\xD4', "{:04X}", "00A1 00B2 00C3 00D4"),  # With leading zeros and fixed width
    (b'\xA1\xB2\xC3\xD4', "{:04x}", "00a1 00b2 00c3 00d4"),  # With leading zeros and fixed width
    (b'\x01\xFF', "{:#04x}", "0x01 0xff"),  # With '0x' prefix and lowercase
    (b'\x0A\x0B\x0C\x0D', "{:#06X}", "0X000A 0X000B 0X000C 0X000D"),  # With '0X' prefix, leading zeros and fixed width
])
def test_hexout_different_formats(byte_data, hex_format, expected):
    # Initialize HexOut with hex_format
    ho = HexOut(hex_format=hex_format)

    # Call and test
    value = ho.as_hex(byte_data)
    assert value == expected

@pytest.mark.parametrize("byte_data, columns, addr_fmt, expected", [
    (b'\x00\x01\x02\x03\x04', 1, "{:02X}: ", "00: 00\n01: 01\n02: 02\n03: 03\n04: 04"),
    (b'\x00\x01\x02\x03\x04', 2,  "{:04X}: ","0000: 00 01\n0002: 02 03\n0004: 04"),
    (b'\x00\x01\x02\x03\x04', 4,  "{:06X}: ", "000000: 00 01 02 03\n000004: 04"),
    (b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F', 8, "{:08X}: ",
     "00000000: 00 01 02 03 04 05 06 07\n00000008: 08 09 0A 0B 0C 0D 0E 0F")
])
def test_hexout_multi_line_address_width(byte_data, columns, addr_fmt, expected):
    ho = HexOut(columns=columns, addr_format= addr_fmt,show_address=True)
    value = ho.as_hex(byte_data)
    assert value == expected

@pytest.mark.parametrize("byte_data, base_address, columns, addr_fmt, expected", [
    (b'\x00\x01\x02\x03\x04', 0x10, 1, "{:02X}: ", "10: 00\n11: 01\n12: 02\n13: 03\n14: 04"),
    (b'\x00\x01\x02\x03\x04', 0x20, 2, "{:04X}: ", "0020: 00 01\n0022: 02 03\n0024: 04"),
    (b'\x00\x01\x02\x03\x04', 0x30, 4, "{:06X}: ", "000030: 00 01 02 03\n000034: 04"),
    (b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F', 0x40, 8, "{:08X}: ",
     "00000040: 00 01 02 03 04 05 06 07\n00000048: 08 09 0A 0B 0C 0D 0E 0F")
])
def test_hexout_multi_line_base_address(byte_data, base_address, columns, addr_fmt, expected):
    ho = HexOut(columns=columns, show_address=True, addr_format=addr_fmt, base_address=base_address)
    value = ho.as_hex(byte_data)
    assert value == expected

@pytest.mark.parametrize('col_separator,base_address,addr_format,expected_output', [
    (' ', 0, '', '0000: 00 01\n0002: 02 03'),  # default to 4 digit address
    (' ', 0x100, '0x{:04x}: ', '0x0100: 00 01\n0x0102: 02 03'),
    ('\t', 0, '{:04x}: ', '0000: 00\t01\n0002: 02\t03'),
    (' ', 0x100, '{:04x}: ', '0100: 00 01\n0102: 02 03'),
    (' | ', 0x200, '{:04x}: ', '0200: 00 | 01\n0202: 02 | 03'),

])
def test_base_address_and_separator(col_separator, base_address, addr_format, expected_output):
    data = b'\x00\x01\x02\x03'
    ho = HexOut(columns=2, show_address=True,addr_format = addr_format, base_address=base_address,col_separator=col_separator)

    value = ho.as_hex(data)
    assert value == expected_output

def test_hexout_smoke():
    byte_data = bytes([i % 256 for i in range(127)])  # reduce data size
    columns = 8
    bytes_per_column = 2
    addr_format = "{:06X}: "
    ho = HexOut(columns=columns,
                    addr_format=addr_format,
                    hex_format = "{:04X}",
                    show_address=True,
                    col_separator=' - ',
                    line_separator='\n\n',
                    bytes_per_column=bytes_per_column)
    result = ho.as_hex(byte_data)

    hex_representation = lambda b: f"{int.from_bytes(b, 'big'):04X}"
    represent_bytes_as_hex = lambda s: ' - '.join(
        hex_representation(byte_data[i:i + bytes_per_column]) for i in
        range(s, min(s + bytes_per_column * columns, len(byte_data)), bytes_per_column)
    )

    expected_output = '\n\n'.join(
        addr_format.format(i * bytes_per_column * columns) + represent_bytes_as_hex(i * bytes_per_column * columns)
        for i in range(0, math.ceil(len(byte_data) / (bytes_per_column * columns)))
    )
    assert result == expected_output.strip()

@pytest.mark.parametrize("byte_data, bytes_per_column, hex_format, expected", [
    (b"\x00\x01\x02\x04", 2, "0b{:016b}", "0b0000000000000001 0b0000001000000100"),
    (b"\x0F\xAF\x3C\x2F", 2, "0b{:016b}", "0b0000111110101111 0b0011110000101111"),
    (b"\xFE\xFF\x00\x01", 2, "0b{:016b}", "0b1111111011111111 0b0000000000000001"),
    (b"\xAA\xBB\xCC\xDD", 1, "0b{:08b}", "0b10101010 0b10111011 0b11001100 0b11011101"),
])
def test_binary_output(byte_data, bytes_per_column, hex_format, expected):
    ho = HexOut(bytes_per_column=bytes_per_column, hex_format=hex_format)
    value = ho.as_hex(byte_data)
    assert value == expected


@pytest.mark.parametrize("byte_data, bytes_per_column, hex_format, expected", [
    (b"\x00\x01\x02\x04", 2, "0b{:016b}", "0000: 0b0000000000000001 0b0000001000000100"),
    (b"\x0F\xAF\x3C\x2F", 2, "0b{:016b}", "0000: 0b0000111110101111 0b0011110000101111"),
    (b"\xFF\xFF\x00\x00", 2, "0b{:016b}", "0000: 0b1111111111111111 0b0000000000000000"),
    (b"\xAA\xBB\xCC\xDD", 1, "0b{:08b}", "0000: 0b10101010 0b10111011 0b11001100 0b11011101"),
])
def test_binary_output_with_address(byte_data, bytes_per_column, hex_format, expected):
    ho = HexOut(bytes_per_column=bytes_per_column, hex_format=hex_format, show_address=True, addr_format="{:04X}: ")
    value = ho.as_hex(byte_data)
    assert value == expected

@pytest.mark.parametrize("collection_type", [list, tuple, bytes])
def test_ascii_dump_from_collections(collection_type):
    """Verify that the expected collection datatypes will work."""

    expect = r"""00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F ................................
20 21 22 23 24 25 26 27 28 29 2A 2B 2C 2D 2E 2F 30 31 32 33 34 35 36 37 38 39 3A 3B 3C 3D 3E 3F  !"#$%&'()*+,-./0123456789:;<=>?
40 41 42 43 44 45 46 47 48 49 4A 4B 4C 4D 4E 4F 50 51 52 53 54 55 56 57 58 59 5A 5B 5C 5D 5E 5F @ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_
60 61 62 63 64 65 66 67 68 69 6A 6B 6C 6D 6E 6F 70 71 72 73 74 75 76 77 78 79 7A 7B 7C 7D 7E 7F `abcdefghijklmnopqrstuvwxyz{|}~.
80 81 82 83 84 85 86 87 88 89 8A 8B 8C 8D 8E 8F 90 91 92 93 94 95 96 97 98 99 9A 9B 9C 9D 9E 9F ................................
A0 A1 A2 A3 A4 A5 A6 A7 A8 A9 AA AB AC AD AE AF B0 B1 B2 B3 B4 B5 B6 B7 B8 B9 BA BB BC BD BE BF ................................
C0 C1 C2 C3 C4 C5 C6 C7 C8 C9 CA CB CC CD CE CF D0 D1 D2 D3 D4 D5 D6 D7 D8 D9 DA DB DC DD DE DF ................................
E0 E1 E2 E3 E4 E5 E6 E7 E8 E9 EA EB EC ED EE EF F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 FA FB FC FD FE FF ................................"""

    # Build the right collection
    coll = collection_type(range(0, 256))
    assert min(coll) == 0
    assert max(coll) == 0xff

    value = HexOut(show_ascii=True, columns=32).as_hex(coll)
    assert expect == value

@pytest.mark.parametrize("byte_data,exception_message", [
    #Lists
    ([-1, 10, 255], 'Byte (-1) at index 0 is < 0'),
    ([256, 10, 255], 'Byte (256) at index 0  is > 0xff/255'),
    ([0, -1, 255], 'Byte (-1) at index 1 is < 0'),
    ([0, 256, 255], 'Byte (256) at index 1  is > 0xff/255'),
    ([0, 10, -1], 'Byte (-1) at index 2 is < 0'),
    ([0, 10, 256], 'Byte (256) at index 2  is > 0xff/255'),

     # Tuples (overkill)
    ((-1, 10, 255), 'Byte (-1) at index 0 is < 0'),
    ((256, 10, 255), 'Byte (256) at index 0  is > 0xff/255'),
    ((0, -1, 255), 'Byte (-1) at index 1 is < 0'),
    ((0, 256, 255), 'Byte (256) at index 1  is > 0xff/255'),
    ((0, 10, -1), 'Byte (-1) at index 2 is < 0'),
    ((0, 10, 256), 'Byte (256) at index 2  is > 0xff/255'),
    # add more test cases as needed
])
def test_yield_check(byte_data, exception_message):
    # Verify that we correctly trigger exceptions for out of range data
    ho = HexOut()
    with pytest.raises(ValueError) as excinfo:
        list(ho._yield_range_check(byte_data))
    assert str(excinfo.value) == exception_message

@pytest.mark.parametrize("byte_data, bytes_per_column, ", [
    (b"\x00\x01\x02\x04", 2),
    (b"\x0F\xAF\x3C\x2F", 2),
    (b"\xFF\xFF\x00\x00", 2),
    (b"\xAA\xBB\xCC\xDD", 1,)
])
def test_binary_output_with_address(byte_data, bytes_per_column):
    # Verify that sunny day range check gives same results.
    ho_with_check = HexOut(bytes_per_column=bytes_per_column,
                           show_address=True, range_check=True, addr_format="{:04X}: ")

    # HexOut instance with range_check=False
    ho_without_check = HexOut(bytes_per_column=bytes_per_column,
                              show_address=True, range_check=False, addr_format="{:04X}: ")

    value_with_check = ho_with_check.as_hex(byte_data)
    value_without_check = ho_without_check.as_hex(byte_data)

    assert value_with_check == value_without_check