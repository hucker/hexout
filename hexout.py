""" Binary to Hexdump Output"""

import warnings
from typing import Generator,Iterable


class HexOut:
    """
    A class to convert byte data into hexadecimal representation, optionally including
    ASCII characters, byte addresses, and custom formatting options.

    Please note that operations are on 8bit binary data.  Strings are 8 bit characters
    in this context. Any ASCII output is provided to be displayed as ASCII using values
    between decimal 32 and 126.

    Of note is the bytes_per_column configuration.  This allows you to specify that
    the data is of different sizes. It defaults to single bytes per column, but if
    you want 16 bit data you can specify bytes_per_column = 2 or 4 bytes per column
    to specify 32 bit data. The bytes are output in big endian format.

    If you have binary data that looks like b"abcdefgh" and ask for

    HexOut(show_address=True,show_ascii=True,columns=4).as_hex(b"abcdefgh)

    00: 32 33 34 35 abcd
    04: 36 37 38 39 efgh


    Class Variables:
        ascii_dict: Dictionary mapping byte values to ASCII characters.

    Instance Variables:
        bytes_per_column: Number of bytes per column in output.
        columns: Number of columns for formatting.
        base_address: Base address to start displaying addresses.
        addr_format: String format for byte addresses.
        show_address: Flag indicating whether addresses should be shown.
        column_separator: Separator between columns in output.
        line_separator: Separator between lines in output.
        hex_format: Format for hexadecimal values.
        show_ascii: Flag indicating whether ASCII characters should be displayed.
        range_check: Flag indicating whether to check for out-of-range byte values.

    Methods:
        generate_hex(byte_data: bytes) -> Generator[str, None, None]:
            Yields line-by-line hexadecimal strings representing the byte data.

        as_hex(byte_data: bytes, line_separator: str = None) -> str:
            Returns a complete hexadecimal string with optional line separation.
    """

    def __init__(self,
                 bytes_per_column: int = 1,
                 columns: int = 0,
                 base_address: int = 0,
                 col_separator: str = " ",
                 line_separator: str = "\n",
                 hex_format: str = "",
                 addr_format: str = "{:04X}: ",
                 show_address: bool = False,
                 show_ascii: bool = False,
                 ascii_pad:str = '.',
                 range_check: bool = True) -> None:
        self.bytes_per_column = bytes_per_column
        self.columns = columns
        self.base_address = base_address
        self.addr_format = addr_format or '{:04X}: '  # This fixes a test case
        self.show_address = show_address
        self.column_separator = col_separator
        self.line_separator = line_separator
        self.hex_format = hex_format or "{:0"+str(bytes_per_column*2)+"X}"
        self.show_ascii = show_ascii
        self.range_check = range_check
        self.byte_order = 'big'

        # Prefilled tuple to map byte values to ASCII characters, using ascii_pad for non-printable
        self.ascii_lookup = tuple(chr(i) if 32 <= i <= 126 else ascii_pad for i in range(256))

        if show_ascii and bytes_per_column != 1:
            warnings.warn("Displaying ascii only works when bytes per column=1.")

    def _yield_bytes_as_ints(self,
                             byte_data: Iterable[int]) -> Generator[int, None, None]:
        """Collect up the bytes into integers and stream those."""
        bytes_in_chunk = []
        for byte in byte_data:
            bytes_in_chunk.append(byte)
            if len(bytes_in_chunk) == self.bytes_per_column:
                yield int.from_bytes(bytes_in_chunk, self.byte_order)
                bytes_in_chunk = []
        if bytes_in_chunk:  # Handle the last chunk if it exists
            yield int.from_bytes(bytes_in_chunk, self.byte_order)

    def _yield_ints_as_list(self,
                            integer_data: Iterable[int])\
            -> Generator[list[int], None, None]:
        """ Collect the ints up in to a list of integers used on a single line. """
        line = []
        for i, data in enumerate(integer_data, 1):
            line.append(data)
            if self.columns > 0 and i % self.columns == 0:
                yield line
                line = []
        if line:  # handle the last column
            yield line

    def make_address(self, i: int) -> str:
        """Return address string for a line."""
        if self.show_address:
            return self.addr_format.format((i * self.bytes_per_column * self.columns)
                                           + self.base_address)
        return ''

    def make_hex(self, line: Iterable[int]) -> str:
        """Return hex string for a line."""
        return self.column_separator.join(self.hex_format.format(num) for num in line)

    def make_ascii(self, line: Iterable[int]) -> str:
        """Generates the ASCII representation of a line, if required."""
        if self.show_ascii and self.bytes_per_column == 1:
            return ' ' + ''.join(self.ascii_lookup[b] for b in line)
        return ''

    def _yield_list_as_string(self, lines:Iterable[int]) \
            -> Generator[str, None, None]:
        """Make the string given the list of integers.

        THere are three possible pieces to a line, the address, the hex and the ascii string.
        This loop passes the required data for each part of the line to helper functions
        """
        for i, line in enumerate(lines):
            yield self.make_address(i) + self.make_hex(line) + self.make_ascii(line)

    def _yield_range_check(self, bytes_:Iterable[int]):
        """
        Verifies that all byte values are within the valid range (0-255).

        This check ensures the byte data doesn't contain invalid values,
        allowing for more precise error reporting when issues occur.

        Args:
            bytes_: The byte data to validate.

        Yields:
            byte: Valid byte values.

        Raises:
            ValueError: If any byte value is out of range (less than 0 or greater than 255).
        """

        for i, byte in enumerate(bytes_):
            if byte < 0:
                raise ValueError(f'Byte ({byte}) at index {i} is < 0')
            if byte > 255:
                raise ValueError(f'Byte ({byte}) at index {i}  is > 0xff/255')
            yield byte

    def generate_hex(self, byte_data: Iterable[int]) -> Generator[str, None, None]:
        """Create a generator that yields line-by-line hexadecimal representing the byte data."""

        # The range check flag could possibly speed things up a tiny bit.
        if self.range_check:
            stage0 = self._yield_range_check(byte_data)
        else:
            stage0 = byte_data
        stage1 = self._yield_bytes_as_ints(stage0)
        stage2 = self._yield_ints_as_list(stage1)
        return self._yield_list_as_string(stage2)

    def as_hex(self, byte_data: bytes, line_separator=None) -> str:
        """Return the full hex string, which is just making a list out of the hex generator."""
        line_separator = line_separator or self.line_separator
        return line_separator.join(self.generate_hex(byte_data))

    def from_file(self,filename:str,line_separator=None)->str:
        """
        Return the hex string reading from a file.
        Note that this has the issue of dealing with large files being read into memory
        rather that streaming the data. Left as an excercise for the reader to
        update this to pass a bytestream to as_hex rather that the fully materialized
        byte data.
        """
        with open(filename, 'rb') as f:
            bytes = f.read()
            line_separator = line_separator or self.line_separator
            return self.as_hex(bytes,line_separator)
