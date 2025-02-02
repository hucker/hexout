""" Binary to Hexdump Output"""

import warnings
from typing import Generator, Iterable, Literal, Optional


class HexOut:
    """
    A class to convert byte data into hexadecimal representation, optionally including
    ASCII characters, byte addresses, and custom formatting options.

    Please note that operations are on 8bit binary data.  Strings are 8 bit characters
    in this context. Any ASCII output is provided to be displayed as ASCII using values
    between decimal 32 and 126.

    Of note is the bytes_per_column configuration.  This allows you to specify that
    the output data size differs. It defaults to single bytes per column, but if
    you want 16-bit data you can specify bytes_per_column = 2 or 4 bytes per column
    to specify 32-bit data. The bytes are output in big endian format.

    If you have binary data that looks like b"abcdefgh" and ask for

    HexOut(show_address=True,show_ascii=True,columns=4).as_hex(b"abcdefgh)

    00: 32 33 34 35 abcd
    04: 36 37 38 39 efgh

    NOTE: methods that start with _ probably should NOT be tested directly.  These
          methods are details of the implementation and should not be called directly.

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
                 ascii_pad: str = '.',
                 fill_byte: Optional[int] = None,
                 str_encode: str='utf8',
                 range_check: bool = True) -> None:
              
        if columns < 0:
            raise ValueError("self.columns must be >= 0")

        if bytes_per_column < 1:
            raise ValueError("self.bytes_per_column must be >= 1")

        if base_address < 0:
            raise ValueError("self.base_address must be >= 0")

        self.bytes_per_column = bytes_per_column
        self.columns = columns
        self.base_address = base_address
        self.addr_format = addr_format or '{:04X}: '  # This fixes a test case
        self.show_address = show_address
        self.column_separator = col_separator
        self.line_separator = line_separator
        self.hex_format = hex_format or "{:0" + str(bytes_per_column * 2) + "X}"
        self.show_ascii = show_ascii
        self.range_check = range_check
        self.byte_order: Literal['little', 'big'] = 'big'  # This quiets mypy and is a bit overkill.
        self.fill_byte = fill_byte
        self.str_encode = str_encode

        # Prefilled tuple to map byte values to ASCII characters, using ascii_pad for non-printable
        self.ascii_lookup = tuple(chr(i) if 32 <= i <= 126 else ascii_pad for i in range(256))

        if show_ascii and bytes_per_column != 1:
            warnings.warn("Displaying ascii only works when bytes_per_column=1.")

    def _yield_bytes_as_ints(self, byte_data: Iterable[int]) -> Generator[int, None, None]:
        """Collect up the bytes into integers and stream those."""
        bytes_in_chunk = []
        for byte in byte_data:
            bytes_in_chunk.append(byte)
            if len(bytes_in_chunk) == self.bytes_per_column:
                yield int.from_bytes(bytes(bytes_in_chunk), self.byte_order)
                bytes_in_chunk = []
        if bytes_in_chunk:  # Handle the last chunk if it exists
            yield int.from_bytes(bytes(bytes_in_chunk), self.byte_order)

    def _yield_ints_as_list(self,
                            integer_data: Iterable[int]) \
            -> Generator[Iterable[int], None, None]:
        """ Collect ints into a list of integers used for a single line of output """
        line = []
        for i, data in enumerate(integer_data, 1):
            line.append(data)
            if self.columns > 0 and i % self.columns == 0:
                yield line
                line = []
        if line:  # handle the last column
            yield line

    def make_address(self, addr: int) -> str:
        """Return address string for a line."""
        if self.show_address:
            return self.addr_format.format((addr * self.bytes_per_column * self.columns)
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

    def _yield_list_as_string(self, integers_in_line: Iterable[Iterable[int]]) \
            -> Generator[str, None, None]:
        """Make the string given the list of integers.

        There are three possible pieces to a line, the address, the hex and the ascii string.
        This loop passes the required data for each part of the line to helper functions
        """
        for i, line in enumerate(integers_in_line):
            yield self.make_address(i) + self.make_hex(line) + self.make_ascii(line)

    def _yield_range_check(self, bytes_: Iterable[int]):
        """Verify byte values are within range (0-255)."""
        
        for count, byte in enumerate(bytes_):
            if self.range_check and not (0 <= byte <= 255):
                raise ValueError(f'Byte ({byte}) at index {count} is out of range (0-255)')
            yield byte

    def _yield_na_to_line_length(self, bytes_: Iterable[int]):
        """
        Fill extra bytes if there are missing bytes.

        Each "line" is based on the columns and the bytes per column.  If
        the line is expecting 8 bytes but the there are only 5 there
        are 3 bytes missing for the line.  This code fills in those bytes
        if a non-None fill byte has been provided.

        Args:
            bytes_: Iterator for byte data.

        Yields:
            byte: Filled bytes.
        """
        line_length = self.columns * self.bytes_per_column

        count = 0
        for byte in bytes_:
            yield byte
            count += 1

        if self.fill_byte is not None and line_length > 1 and count % line_length > 0:
            remainder = line_length - (count % line_length)
            for b in range(remainder):
                yield self.fill_byte

    def generate_hex(self, byte_data: Iterable[int]) -> Generator[str, None, None]:
        """Create a generator that yields line-by-line hexadecimal representing the byte data."""

        stage0 = self._yield_range_check(byte_data)
        stage1 = self._yield_na_to_line_length(stage0)
        stage2 = self._yield_bytes_as_ints(stage1)
        stage3 = self._yield_ints_as_list(stage2)
        return self._yield_list_as_string(stage3)

    def as_hex(self, byte_data: bytes, encoding = None, line_separator=None) -> str:
        """Return the full hex string, which is just making a list out of the hex generator."""
        
        # Give them a shot to override.
        encoding = encoding or self.str_encode
        
        if isinstance(byte_data, str):
            byte_data = byte_data.encode(encoding)
        
        line_separator = line_separator or self.line_separator
        return line_separator.join(self.generate_hex(byte_data))

    def from_file(self, filename: str, line_separator=None) -> str:
        """
        Return the hex string reading from a file.
        Note that this has the issue of dealing with large files being read into memory
        rather that streaming the data. Left as an exercise for the reader to
        update this to pass a bytestream to as_hex rather that the fully materialized
        byte data.
        """
        with open(filename, 'rb') as f:
            bytes_ = f.read()
            line_separator = line_separator or self.line_separator
            return self.as_hex(bytes_, line_separator)
