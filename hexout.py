import warnings
from typing import Generator,Iterable


class HexOut:
    """
    HexOut class constructs a pipeline to translate byte data into hexadecimal strings.

    The class can also optionally include the original ASCII characters,
    the byte addresses and can format the hexadecimal strings as per user desired configurations.

    Class Variables:
        ascii_dict: Mapping dictionary for byte values to ASCII characters.

    Instance Variables:
        bytes_per_column: Number of bytes per column.
        columns: Number of columns.
        base_address: Base value used when addresses are shown.
        addr_format: Address formatting string.
        show_address: Flag to decide if addresses should be displayed.
        column_separator: String to use as separator between columns.
        line_separator: String to use as separator between lines.
        hex_format: Hexadecimal format.
        show_ascii: Flag to decide if ASCII representation should be displayed.
        range_check: Flag to decide to run range checks on "binary" data.

    Methods:
        generate_hex(byte_data: bytes) -> Generator[str, None, None]:
            Yields line-by-line hexadecimal strings that represent the byte data.

        as_hex(byte_data: bytes, line_separator=None) -> str:
            Returns a string of hexadecimal representation of byte data separated by lines.
    """

    # This dictionary maps byte values to printable text.  It only needs to be created once
    # for the class.
    ascii_dict = {i: chr(i) if 32 <= i <= 126 else '.' for i in range(256)}  # This

    def __init__(self, bytes_per_column: int = 1, columns: int = 0, base_address: int = 0, col_separator: str = " ",
                 line_separator: str = "\n",
                 hex_format: str = "{:02X}",
                 addr_format: str = "{:04X}: ",
                 show_address: bool = False,
                 show_ascii: bool = False,
                 range_check: bool = True) -> None:
        self.bytes_per_column = bytes_per_column
        self.columns = columns
        self.base_address = base_address
        self.addr_format = addr_format or '{:04X}: '  # This fixes a test case
        self.show_address = show_address
        self.column_separator = col_separator
        self.line_separator = line_separator
        self.hex_format = hex_format or "{:02X}"
        self.show_ascii = show_ascii
        self.range_check = range_check

        if show_ascii and bytes_per_column != 1:
            warnings.warn("Displaying ascii only works when bytes per column=1.")

    def _yield_bytes_as_ints(self, byte_data: Generator[int, None, None]) -> Generator[int, None, None]:
        """Collect up the bytes into integers and stream those."""
        bytes_in_chunk = []
        for byte in byte_data:
            bytes_in_chunk.append(byte)
            if len(bytes_in_chunk) == self.bytes_per_column:
                yield int.from_bytes(bytes_in_chunk, 'big')
                bytes_in_chunk = []
        if bytes_in_chunk:  # Handle the last chunk if it exists
            yield int.from_bytes(bytes_in_chunk, 'big')

    def _yield_ints_as_list(self, integer_data: Generator[int, None, None]) -> Generator[list[int], None, None]:
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
            return self.addr_format.format((i * self.bytes_per_column * self.columns) + self.base_address)
        else:
            return ''

    def make_hex(self, line: Iterable[int]) -> str:
        """Return hex string for a line."""
        return self.column_separator.join(self.hex_format.format(num) for num in line)

    def make_ascii(self, line: Iterable[int]) -> str:
        """Return ascii string for a line."""
        if self.show_ascii and self.bytes_per_column == 1:
            return ' ' + ''.join(HexOut.ascii_dict[b] for b in line)
        else:
            return ''

    def _yield_lines_as_string(self, lines: Generator[list[int], None, None]) -> Generator[str, None, None]:
        """Make the string given the list of integers.

        THere are three possible pieces to a line, the address, the hex and the ascii string.
        This loop passes the required data for each part of the line to helper functions
        """
        for i, line in enumerate(lines):
            yield self.make_address(i) + self.make_hex(line) + self.make_ascii(line)

    def _yield_range_check(self, bytes):
        """
        Verify al bytes are in range

        If you know your data this might not be needed, but including this stage
        in the pipeline will allow for error messages that are precise in giving
        data that allows errors to be pinpointed.
        """

        for i, byte in enumerate(bytes):
            if byte < 0:
                raise ValueError(f'Byte ({byte}) at index {i} is < 0')
            elif byte > 255:
                raise ValueError(f'Byte ({byte}) at index {i}  is > 0xff/255')
            yield byte

    def generate_hex(self, byte_data: bytes) -> Generator[str, None, None]:
        """Create a generator that yields line-by-line hexadecimal representing the byte data."""

        # The range check flag can
        if self.range_check:
            stage0 = self._yield_range_check(byte_data)
        else:
            stage0 = byte_data
        stage1 = self._yield_bytes_as_ints(stage0)
        stage2 = self._yield_ints_as_list(stage1)
        return self._yield_lines_as_string(stage2)

    def as_hex(self, byte_data: bytes, line_separator=None) -> str:
        """Return the full hex string, which is just making a list out of the hex generator."""
        line_separator = line_separator or self.line_separator
        return line_separator.join(self.generate_hex(byte_data))
