# HexOut

`hexout` is a library that generates hex listings of binary data in a flexible form this
is most commonly useful when dealing with binary file data, packet data and data commonly occuring
in embedded systems work.

## Basic Usage

`Hexout` generates hex dumps of binary data.  Viewing data in hex is useful any time processing
binary data is in play. 

The main data types that are expected are byte strings, strings, lists/tuples of integers in the range 
0/255.  For example:

```python
seq = b'\x01\x02'
seq = 'this is a test'   # interpreted as utf8
seq = [1,2]
seq = (1,2)

# and for bonus

def my_seq():
   yield 0
   yield 1


```

The default hex format is inferred to be `0widthX`, the standard hex formatting with leading 0 and
upper case hex letters.  The `width` is `2*bytes_per_column`, since each byte requires 2 ascii characters
to represent it.  If you want leading 0x, or no zero padding you can pass in a custom format.

### Examples:

Most simple output of raw bytes.
```text
HexOut().as_hex(b'\x01\x02\x03')
'01 02 03'
```

Now some formatting
```text
HexOut(bytes_per_column=2,hex_format='0x{:04x}').as_hex(b'\x01\x02\x03\04')
'0x0102 0x0304'
```

Now with address:
```text
HexOut(show_address=True,bytes_per_column=2,hex_format='0x{:04x}').as_hex(b'\x01\x02\x03\04')
'0000: 0x0102 0x0304'
```

Now for some bigger examples:

Regular hex data as a list of 32 bit hex values.

```text
>>>bdata = list(range(0,256))
>>>ho = HexOut(columns=8,bytes_per_column=4,hex_format='0x{:08X}',addr_format='0x{:02X}: ',show_address=True)
>>>print(ho.as_hex(bdata))
0x00: 0x00010203 0x04050607 0x08090A0B 0x0C0D0E0F 0x10111213 0x14151617 0x18191A1B 0x1C1D1E1F
0x20: 0x20212223 0x24252627 0x28292A2B 0x2C2D2E2F 0x30313233 0x34353637 0x38393A3B 0x3C3D3E3F
0x40: 0x40414243 0x44454647 0x48494A4B 0x4C4D4E4F 0x50515253 0x54555657 0x58595A5B 0x5C5D5E5F
0x60: 0x60616263 0x64656667 0x68696A6B 0x6C6D6E6F 0x70717273 0x74757677 0x78797A7B 0x7C7D7E7F
0x80: 0x80818283 0x84858687 0x88898A8B 0x8C8D8E8F 0x90919293 0x94959697 0x98999A9B 0x9C9D9E9F
0xA0: 0xA0A1A2A3 0xA4A5A6A7 0xA8A9AAAB 0xACADAEAF 0xB0B1B2B3 0xB4B5B6B7 0xB8B9BABB 0xBCBDBEBF
0xC0: 0xC0C1C2C3 0xC4C5C6C7 0xC8C9CACB 0xCCCDCECF 0xD0D1D2D3 0xD4D5D6D7 0xD8D9DADB 0xDCDDDEDF
0xE0: 0xE0E1E2E3 0xE4E5E6E7 0xE8E9EAEB 0xECEDEEEF 0xF0F1F2F3 0xF4F5F6F7 0xF8F9FAFB 0xFCFDFEFF
```
or a list of 8bit hex values
```text
>>>bdata = list(range(0,256))
>>>print(HexOut(bytes_per_column=1, columns=16,hex_format='{:02X}').as_hex(bdata))
00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F
20 21 22 23 24 25 26 27 28 29 2A 2B 2C 2D 2E 2F
30 31 32 33 34 35 36 37 38 39 3A 3B 3C 3D 3E 3F
40 41 42 43 44 45 46 47 48 49 4A 4B 4C 4D 4E 4F
50 51 52 53 54 55 56 57 58 59 5A 5B 5C 5D 5E 5F
60 61 62 63 64 65 66 67 68 69 6A 6B 6C 6D 6E 6F
70 71 72 73 74 75 76 77 78 79 7A 7B 7C 7D 7E 7F
80 81 82 83 84 85 86 87 88 89 8A 8B 8C 8D 8E 8F
90 91 92 93 94 95 96 97 98 99 9A 9B 9C 9D 9E 9F
A0 A1 A2 A3 A4 A5 A6 A7 A8 A9 AA AB AC AD AE AF
B0 B1 B2 B3 B4 B5 B6 B7 B8 B9 BA BB BC BD BE BF
C0 C1 C2 C3 C4 C5 C6 C7 C8 C9 CA CB CC CD CE CF
D0 D1 D2 D3 D4 D5 D6 D7 D8 D9 DA DB DC DD DE DF
E0 E1 E2 E3 E4 E5 E6 E7 E8 E9 EA EB EC ED EE EF
F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 FA FB FC FD FE FF
```
Although the library is called `hexout`, it really can do anything the format statement will tolerate
so the following example shows the output in binary

```text
>>>HexOut( columns=4,hex_format='{:08b}').as_hex(b'\x01\x02\x03\04')
'00000001 00000010 00000011 00000100'
```

This shows most of the capability with addresses, hex, and ascii output.

```text
print(HexOut(show_ascii=True,columns=16).as_hex(range(0,256)))
00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F ................
10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F ................
20 21 22 23 24 25 26 27 28 29 2A 2B 2C 2D 2E 2F  !"#$%&'()*+,-./
30 31 32 33 34 35 36 37 38 39 3A 3B 3C 3D 3E 3F 0123456789:;<=>?
40 41 42 43 44 45 46 47 48 49 4A 4B 4C 4D 4E 4F @ABCDEFGHIJKLMNO
50 51 52 53 54 55 56 57 58 59 5A 5B 5C 5D 5E 5F PQRSTUVWXYZ[\]^_
60 61 62 63 64 65 66 67 68 69 6A 6B 6C 6D 6E 6F `abcdefghijklmno
70 71 72 73 74 75 76 77 78 79 7A 7B 7C 7D 7E 7F pqrstuvwxyz{|}~.
80 81 82 83 84 85 86 87 88 89 8A 8B 8C 8D 8E 8F ................
90 91 92 93 94 95 96 97 98 99 9A 9B 9C 9D 9E 9F ................
A0 A1 A2 A3 A4 A5 A6 A7 A8 A9 AA AB AC AD AE AF ................
B0 B1 B2 B3 B4 B5 B6 B7 B8 B9 BA BB BC BD BE BF ................
C0 C1 C2 C3 C4 C5 C6 C7 C8 C9 CA CB CC CD CE CF ................
D0 D1 D2 D3 D4 D5 D6 D7 D8 D9 DA DB DC DD DE DF ................
E0 E1 E2 E3 E4 E5 E6 E7 E8 E9 EA EB EC ED EE EF ................
F0 F1 F2 F3 F4 F5 F6 F7 F8 F9 FA FB FC FD FE FF ................
```

You can control the number of bytes displayed in each column using the bytes_per_column.

```python
print(HexOut(bytes_per_column=1).as_hex(range(16)))
00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F

print(HexOut(bytes_per_column=2).as_hex(range(16)))
0001 0203 0405 0607 0809 0A0B 0C0D 0E0F

print(HexOut(bytes_per_column=4).as_hex(range(16)))
00010203 04050607 08090A0B 0C0D0E0F

print(HexOut(bytes_per_column=8).as_hex(range(16)))
0001020304050607 08090A0B0C0D0E0F

print(HexOut(bytes_per_column=16).as_hex(range(16)))
000102030405060708090A0B0C0D0E0F
```

If you don't like leading 0's in your number formats you can use spaces by providing a custom hex format
like this where you use the ` >` using the first character (space) as the pad character and the left or
right padding using the `<` or `>` to indicate the padding direction.

```text
print(hexout.HexOut(bytes_per_column=2, hex_format="{: >4X}",columns=4).as_hex(range(32)))
   1  203  405  607
 809  A0B  C0D  E0F
1011 1213 1415 1617
1819 1A1B 1C1D 1E1F
```


## Exceptions
If data is provided that is out of the range for bytes (0-255) a `ValueError` exception is thrown.

## Code Metrics

1. 100% Test Coverage (tox 3.9->3.13)
2. 100% Lint (3.12)
3. 100% Mypy (3.12)



