import tkinter as tk
from tkinter import messagebox, scrolledtext
import re
import os
import math
import struct
from PIL import Image, ImageTk
from datetime import datetime
import sys

# Global variables
_current_bit_addr = -1
_current_bit_value = -1 
bytes_data = []
addr_map = {}
explanations = {}
a2h_explanations = {}
bit_entries = []

def resource_path(relative_path):
    """获取资源文件路径，优先使用exe同目录下的文件"""
    # 首先尝试exe同目录下的文件
    exe_dir = os.path.dirname(os.path.abspath(sys.argv[0]))
    external_path = os.path.join(exe_dir, relative_path)
    
    if os.path.exists(external_path):
        return external_path
    
    # 如果外部文件不存在，使用打包内的文件（仅用于图片等必需资源）
    if hasattr(sys, '_MEIPASS'):
        return os.path.join(sys._MEIPASS, relative_path)
    else:
        return os.path.join(os.path.dirname(__file__), relative_path)

def load_explanations_from_file(filename="A0h_bits_explanation.txt", a2h_filename="A2h_bits_explanation.txt"):
    """
    Loads the explanations dictionaries from two separate text files.
    Each file is expected to contain a Python dictionary literal.
    """
    global explanations, a2h_explanations
    
    def load_single_file(filepath, file_type, default_key=0):
        """Helper function to load a single explanation file"""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
                return eval(content)  # Consider using json.loads() or ast.literal_eval() for security
        except FileNotFoundError:
            messagebox.showerror("Error", f"Explanation file '{os.path.basename(filepath)}' not found.")
            return {default_key: [f"No {file_type} explanations loaded. Please check {os.path.basename(filepath)}"]}
        except (SyntaxError, ValueError) as e:
            messagebox.showerror("Error", f"Error parsing '{os.path.basename(filepath)}': {e}")
            return {default_key: [f"Error parsing {file_type} explanation file. Check syntax."]}
        except Exception as e:
            messagebox.showerror("Error", f"Unexpected error loading '{os.path.basename(filepath)}': {e}")
            return {default_key: [f"Unexpected error loading {file_type} explanations."]}
    
    # Load both explanation files
    explanations = load_single_file(resource_path(filename), "A0h")
    a2h_explanations = load_single_file(resource_path(a2h_filename), "A2h")



def format_hex_bytes(parsed_bytes):
    """将解析出的字节重新格式化为标准显示格式"""
    formatted_parts = []
    for i, byte_val in enumerate(parsed_bytes):
        formatted_parts.append(f"{byte_val:02X}")
        # 每16个字节换行
        if (i + 1) % 16 == 0 and (i + 1) < len(parsed_bytes):
            formatted_parts.append('\n')
        elif (i + 1) < len(parsed_bytes):
            formatted_parts.append(' ')
    return "".join(formatted_parts)

def parse_hex_string(data):
    # Parses a hexadecimal string into a list of integers.
    # First, try to extract data from the simple A0h/A2h format
    extracted_data = extract_from_simple_format(data)
    if extracted_data:
        return extracted_data  # Return the dictionary for special handling
    
    # Then try to extract data from the specific format you mentioned
    extracted_data = extract_from_specific_format(data)
    if extracted_data:
        # Check if it's a dictionary with both a0h and a2h data
        if isinstance(extracted_data, dict):
            return extracted_data  # Return the dictionary for special handling
        else:
            data = extracted_data  # Single string data
    else:
        # Try to extract data from i2cdump format
        extracted_data = extract_from_i2cdump_format(data)
        if extracted_data:
            # Check if it's a dictionary with both a0h and a2h data
            if isinstance(extracted_data, dict):
                return extracted_data  # Return the dictionary for special handling
            else:
                data = extracted_data  # Single string data
    
    # Cleans the input, replacing newlines, commas, and "0x" prefixes.
    data = data.replace("\n", " ").replace(",", " ").replace("0x", " ")
    # Filters out valid two-character hex values.
    hex_values = [x for x in data.strip().split() if len(x) == 2]
    try:
        # Converts hexadecimal strings to integers.
        return [int(x, 16) for x in hex_values]
    except ValueError:
        # Returns an empty list if conversion fails (e.g., invalid hex characters).
        return []

def extract_from_i2cdump_format(data):
    """
    Extract hex data from i2cdump format:
    root@radio2267:# i2cdump -f -y 0 0x50
    No size specified (using byte-data access)
     0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f    0123456789abcdef
    00: 03 04 07 00 00 00 00 00 00 00 00 06 ff 00 0a 64    ???........?..?d
    10: 00 00 00 00 45 52 49 43 53 53 4f 4e 20 20 20 20    ....ERICSSON    
    ...
    
    Also supports multiple i2cdump outputs (0x50 and 0x51) in the same data
    """
    # Check if the data contains i2cdump format pattern
    if "i2cdump" in data or (re.search(r'^\s*[0-9a-fA-F]{2}:', data, re.MULTILINE)):
        # Check if this contains both 0x50 and 0x51 dumps
        if "0x50" in data and "0x51" in data:
            # Split the data into A0h (0x50) and A2h (0x51) sections
            a0h_data, a2h_data = split_i2cdump_data(data)
            return {'a0h': a0h_data, 'a2h': a2h_data}
        else:
            # Single dump - extract normally
            hex_data = []
            lines = data.split('\n')
            
            for line in lines:
                # Look for lines that start with 2-digit hex address followed by colon and hex data
                match = re.match(r'^\s*([0-9a-fA-F]{2}):\s+([0-9a-fA-F\s]+)', line.strip())
                if match:
                    hex_part = match.group(2)
                    # Split by spaces and extract valid 2-character hex values
                    hex_bytes = []
                    for token in hex_part.split():
                        if len(token) == 2 and re.match(r'^[0-9a-fA-F]{2}$', token):
                            hex_bytes.append(token)
                        else:
                            # Stop when we hit non-hex data (ASCII representation)
                            break
                    hex_data.extend(hex_bytes)
            
            if hex_data:
                return ' '.join(hex_data)
    
    return None

def split_i2cdump_data(data):
    """
    Split combined i2cdump data containing both 0x50 and 0x51 dumps
    Returns tuple (a0h_data, a2h_data) as hex strings
    """
    lines = data.split('\n')
    a0h_hex = []
    a2h_hex = []
    current_section = None
    
    for line in lines:
        # Detect which section we're in based on the i2cdump command
        if "i2cdump" in line and "0x50" in line:
            current_section = 'a0h'
            continue
        elif "i2cdump" in line and "0x51" in line:
            current_section = 'a2h'
            continue
        
        # Extract hex data from lines with address:data format
        match = re.match(r'^\s*([0-9a-fA-F]{2}):\s+([0-9a-fA-F\s]+)', line.strip())
        if match and current_section:
            hex_part = match.group(2)
            hex_bytes = []
            for token in hex_part.split():
                if len(token) == 2 and re.match(r'^[0-9a-fA-F]{2}$', token):
                    hex_bytes.append(token)
                else:
                    break
            
            if current_section == 'a0h':
                a0h_hex.extend(hex_bytes)
            elif current_section == 'a2h':
                a2h_hex.extend(hex_bytes)
    
    a0h_data = ' '.join(a0h_hex) if a0h_hex else None
    a2h_data = ' '.join(a2h_hex) if a2h_hex else None
    
    return a0h_data, a2h_data

def extract_from_simple_format(data):
    """
    Extract hex data from simple A0h/A2h format:
    A0h
    03040720 00000012 00014006 67000A64  (8-char groups)
    OR
    03 04 07 20 00 00 00 12 00 01 40 06  (2-char bytes)
    ...
    A2h
    5D00D000 5800D500 8DCC7404 88A4792C  (8-char groups)
    OR
    5d 00 d0 00 58 00 d5 00 8d cc 74 04  (2-char bytes)
    ...
    """
    # Check if the data contains simple A0h/A2h markers
    if re.search(r'^\s*A0h\s*$', data, re.MULTILINE) and re.search(r'^\s*A2h\s*$', data, re.MULTILINE):
        lines = data.split('\n')
        a0h_hex = []
        a2h_hex = []
        current_section = None
        
        for line in lines:
            line = line.strip()
            # Detect section markers
            if re.match(r'^A0h\s*$', line):
                current_section = 'a0h'
                continue
            elif re.match(r'^A2h\s*$', line):
                current_section = 'a2h'
                continue
            
            # Extract hex data from lines
            if current_section and line:
                # First try to find 8-character hex groups
                hex_groups = re.findall(r'[0-9A-Fa-f]{8}', line)
                if hex_groups:
                    # Process 8-char groups
                    for group in hex_groups:
                        # Split each 8-char group into 4 bytes
                        for i in range(0, 8, 2):
                            hex_byte = group[i:i+2]
                            if current_section == 'a0h':
                                a0h_hex.append(hex_byte)
                            elif current_section == 'a2h':
                                a2h_hex.append(hex_byte)
                else:
                    # Try to find 2-character hex bytes
                    hex_bytes = re.findall(r'[0-9A-Fa-f]{2}', line)
                    for hex_byte in hex_bytes:
                        if current_section == 'a0h':
                            a0h_hex.append(hex_byte)
                        elif current_section == 'a2h':
                            a2h_hex.append(hex_byte)
        
        if a0h_hex or a2h_hex:
            a0h_data = ' '.join(a0h_hex) if a0h_hex else None
            a2h_data = ' '.join(a2h_hex) if a2h_hex else None
            return {'a0h': a0h_data, 'a2h': a2h_data}
    
    return None

def extract_from_specific_format(data):
    """
    Extract hex data from the specific format:
    Address Data                                Data
    Hex     Hex                                 Bin
    ----    -------- -------- -------- -------- ------------------
    0000    03040720 00000012 00014006 67000A64 "... ......@.g..d"
    
    Also supports automatic separation of A0h and A2h data based on page indicators
    """
    import re
    
    # Check if the data contains the specific format pattern
    if "Address Data" in data and "Hex     Hex" in data:
        # Check if this contains both A0h and A2h sections
        if ("A0h" in data or "EEPROM" in data) and ("A2h" in data or "DDM" in data):
            # Split the data into A0h and A2h sections
            a0h_data, a2h_data = split_specific_format_data(data)
            return {'a0h': a0h_data, 'a2h': a2h_data}
        else:
            # Single section - extract normally
            hex_data = []
            lines = data.split('\n')
            
            for line in lines:
                # Look for lines that start with 4-digit hex address followed by hex data
                match = re.match(r'^([0-9A-Fa-f]{4})\s+([0-9A-Fa-f\s]+)\s+["&].*["&]\s*$', line.strip())
                if match:
                    hex_part = match.group(2).strip()
                    # Remove spaces and extract all hex bytes (groups of 8 hex chars)
                    hex_groups = re.findall(r'[0-9A-Fa-f]{8}', hex_part.replace(' ', ''))
                    for group in hex_groups:
                        # Split each 8-char group into 4 bytes
                        for i in range(0, 8, 2):
                            hex_data.append(group[i:i+2])
            
            if hex_data:
                return ' '.join(hex_data)
    
    return None

def split_specific_format_data(data):
    """
    Split specific format data containing both A0h and A2h sections
    Returns tuple (a0h_data, a2h_data) as hex strings
    """
    import re
    
    lines = data.split('\n')
    a0h_hex = []
    a2h_hex = []
    current_section = None
    
    for line in lines:
        # Detect which section we're in based on page indicators
        if "A0h" in line or ("EEPROM" in line and "A0h" in line):
            current_section = 'a0h'
            continue
        elif "A2h" in line or ("DDM" in line and "A2h" in line):
            current_section = 'a2h'
            continue
        
        # Extract hex data from lines with address:data format
        match = re.match(r'^([0-9A-Fa-f]{4})\s+([0-9A-Fa-f\s]+)\s+["&].*["&]\s*$', line.strip())
        if match and current_section:
            hex_part = match.group(2).strip()
            # Remove spaces and extract all hex bytes (groups of 8 hex chars)
            hex_groups = re.findall(r'[0-9A-Fa-f]{8}', hex_part.replace(' ', ''))
            hex_bytes = []
            for group in hex_groups:
                # Split each 8-char group into 4 bytes
                for i in range(0, 8, 2):
                    hex_bytes.append(group[i:i+2])
            
            if current_section == 'a0h':
                a0h_hex.extend(hex_bytes)
            elif current_section == 'a2h':
                a2h_hex.extend(hex_bytes)
    
    a0h_data = ' '.join(a0h_hex) if a0h_hex else None
    a2h_data = ' '.join(a2h_hex) if a2h_hex else None
    
    return a0h_data, a2h_data

def get_ascii(data, start, end):
    # Extracts a string from a portion of byte data
    # If a byte is not a printable ASCII character (0x20-0x7E), it's displayed as its hex value
    ascii_chars = []
    for b in data[start:end]:
        if 0x20 <= b <= 0x7E: # Check if within printable ASCII range (space to tilde)
            ascii_chars.append(chr(b))
        else:
            ascii_chars.append(f"{b:02X}") # Display as two-digit hex if not printable
    return ''.join(ascii_chars).strip()

def get_u16(data, offset, scale=1.0):
    # Reads an unsigned 16-bit integer from byte data at a given offset
    # Applies an optional scale factor
    if offset + 1 >= len(data): return None # Ensure enough bytes are available
    # Combines two bytes into a 16-bit unsigned integer
    return ((data[offset] << 8) | data[offset + 1]) * scale

def get_s16(data, offset, scale=1.0):
    # Reads a signed 16-bit integer from byte data at a given offset
    # Applies an optional scale factor. Handles two's complement.
    if offset + 1 >= len(data): return None # Ensure enough bytes are available
    # Combines two bytes into a 16-bit integer
    val = (data[offset] << 8) | (data[offset + 1])
    # Checks if the most significant bit is set (indicating a negative number)
    if val & 0x8000:
        val -= 0x10000 # Converts two's complement to signed integer
    return val * scale

def get_float32(data, offset):
    # Reads a 4-byte single precision floating point number (IEEE 754)
    # from byte data at a given offset. Assumes big-endian (MSB at lowest address).
    if offset + 3 >= len(data): return None # Ensure enough bytes are available
    byte_string = bytes(data[offset:offset+4])
    try:
        # '>f' means big-endian float (single precision)
        return struct.unpack('>f', byte_string)[0]
    except struct.error:
        return None # In case of malformed byte string

def format_binary(value):
    # Formats an integer as an 8-bit binary string
    return format(value, '08b')

def explain_bits(addr, val):
    # Provides bit-level explanations for specific register addresses
    # This function now uses the globally loaded 'explanations' dictionary
    # It distinguishes between A0h and A2h addresses.

    display_addr_str = ""
    explanation_list = []
    
    if 0 <= addr <= 255: # A0h address space
        display_addr_str = f"Byte {addr}"
        explanation_list = explanations.get(addr, [f"{display_addr_str}", "No specific explanation available for this A0h address.", "7-0: Unallocated / Reserved"])
    elif 256 <= addr <= 511: # A2h address space
        relative_a2h_addr = addr - 256
        display_addr_str = f"A2h Byte {relative_a2h_addr}"
        explanation_list = a2h_explanations.get(relative_a2h_addr, [f"{display_addr_str}", "No specific explanation available for this A2h address.", "7-0: Unallocated / Reserved"])
    else:
        display_addr_str = f"Invalid Address {addr}"
        explanation_list = [f"{display_addr_str}", "Address out of valid SFP+ range (0-511)."]

    bits = format_binary(val)
    hex_val = f"0x{val:02X}" # Get hexadecimal representation
    
    # Prepend the byte number, hexadecimal value, and binary value, followed by the explanation lines.
    result_str = f"{display_addr_str}: HEX:{hex_val} Binary: {bits}\n" + "\n".join(explanation_list)

    # Update the 8 individual bit entry boxes
    for i in range(8):
        bit_entries[i].delete(0, tk.END)
        bit_entries[i].insert(0, bits[i])

    return result_str


def update_line_numbers():
    # Updates the line number display in the line_numbers_text widget
    line_numbers_a0h.config(state='normal')
    line_numbers_a0h.delete("1.0", tk.END)
    for i in range(0, 256, 16):
        line_numbers_a0h.insert(tk.END, f"A0h {i:02X}\n") # E.g., "A0h 00", "A0h 10"
    line_numbers_a0h.config(state='disabled')

    line_numbers_a2h.config(state='normal')
    line_numbers_a2h.delete("1.0", tk.END)
    for i in range(0, 256, 16):
        line_numbers_a2h.insert(tk.END, f"A2h {i:02X}\n") # E.g., "A2h 00", "A2h 10"
    line_numbers_a2h.config(state='disabled')

def get_bit_status(byte_value, bit_position, name):
    """Returns a string indicating the status of a specific bit (Active/Inactive)."""
    status = "Active (1)" if (byte_value & (1 << bit_position)) else "Inactive (0)"
    return f"Bit {bit_position}: {name} ({status})"
    

def parse_registers():
    # Parses SFP register data from the input text area based on byte count conditions
    raw_a0h = input_text.get("1.0", tk.END)
    raw_a2h = input_a2h_text.get("1.0", tk.END)
    
    # Check if the input contains i2cdump format with both 0x50 and 0x51
    combined_data = raw_a0h + "\n" + raw_a2h
    if "i2cdump" in combined_data and "0x50" in combined_data and "0x51" in combined_data:
        # Handle combined i2cdump format
        extracted_data = extract_from_i2cdump_format(combined_data)
        if isinstance(extracted_data, dict):
            # Auto-populate both input fields
            if extracted_data['a0h']:
                parsed_a0h_bytes = [int(x, 16) for x in extracted_data['a0h'].split()]
                formatted_a0h = format_hex_bytes(parsed_a0h_bytes)
                input_text.delete("1.0", tk.END)
                input_text.insert("1.0", formatted_a0h)
                raw_a0h = formatted_a0h
            
            if extracted_data['a2h']:
                parsed_a2h_bytes = [int(x, 16) for x in extracted_data['a2h'].split()]
                formatted_a2h = format_hex_bytes(parsed_a2h_bytes)
                input_a2h_text.delete("1.0", tk.END)
                input_a2h_text.insert("1.0", formatted_a2h)
                raw_a2h = formatted_a2h
    
    # Check if A0h input contains simple A0h/A2h format
    elif re.search(r'^\s*A0h\s*$', raw_a0h, re.MULTILINE) and re.search(r'^\s*A2h\s*$', raw_a0h, re.MULTILINE):
        # Handle simple A0h/A2h format
        extracted_data = extract_from_simple_format(raw_a0h)
        if isinstance(extracted_data, dict):
            # Auto-populate both input fields
            if extracted_data['a0h']:
                parsed_a0h_bytes = [int(x, 16) for x in extracted_data['a0h'].split()]
                formatted_a0h = format_hex_bytes(parsed_a0h_bytes)
                input_text.delete("1.0", tk.END)
                input_text.insert("1.0", formatted_a0h)
                raw_a0h = formatted_a0h
            
            if extracted_data['a2h']:
                parsed_a2h_bytes = [int(x, 16) for x in extracted_data['a2h'].split()]
                formatted_a2h = format_hex_bytes(parsed_a2h_bytes)
                input_a2h_text.delete("1.0", tk.END)
                input_a2h_text.insert("1.0", formatted_a2h)
                raw_a2h = formatted_a2h
    
    # Check if A0h input contains special format with both A0h and A2h data
    elif ("Address Data" in raw_a0h and "A0h" in raw_a0h and "A2h" in raw_a0h) or ("EEPROM" in raw_a0h and "DDM" in raw_a0h):
        # Handle combined special format
        extracted_data = extract_from_specific_format(raw_a0h)
        if isinstance(extracted_data, dict):
            # Auto-populate both input fields
            if extracted_data['a0h']:
                parsed_a0h_bytes = [int(x, 16) for x in extracted_data['a0h'].split()]
                formatted_a0h = format_hex_bytes(parsed_a0h_bytes)
                input_text.delete("1.0", tk.END)
                input_text.insert("1.0", formatted_a0h)
                raw_a0h = formatted_a0h
            
            if extracted_data['a2h']:
                parsed_a2h_bytes = [int(x, 16) for x in extracted_data['a2h'].split()]
                formatted_a2h = format_hex_bytes(parsed_a2h_bytes)
                input_a2h_text.delete("1.0", tk.END)
                input_a2h_text.insert("1.0", formatted_a2h)
                raw_a2h = formatted_a2h
    
    # 1. 判断是否包含有效的十六进制数据
    # 支持十六进制字符 '0-9', 'a-f', 'A-F', 空格, 换行符, 逗号, 以及 '0x' 前缀
    # 同时支持特定格式的数据（包含Address Data等标识符）和i2cdump格式
    hex_pattern = r"[\da-fA-Fx\s,\n\r\"\-:]+"
    if not re.fullmatch(hex_pattern, raw_a0h) and not ("Address Data" in raw_a0h) and not ("i2cdump" in raw_a0h or re.search(r'^\s*[0-9a-fA-F]{2}:', raw_a0h, re.MULTILINE)):
        messagebox.showwarning("Data Format Error", "A0h Strings contain invalid characters!")
        return
    if not re.fullmatch(hex_pattern, raw_a2h) and not ("Address Data" in raw_a2h) and not ("i2cdump" in raw_a2h or re.search(r'^\s*[0-9a-fA-F]{2}:', raw_a2h, re.MULTILINE)):
        messagebox.showwarning("Data Format Error", "A2h Strings contain invalid characters!")
        return

    # 解析可用的十六进制字符串（现在支持0x格式、特定格式和i2cdump格式）
    parsed_a0h_bytes = parse_hex_string(raw_a0h)
    parsed_a2h_bytes = parse_hex_string(raw_a2h)
    
    # 通用自动分离：如果A0h输入超过256字节，自动分离（无论A2h是否有内容）
    if isinstance(parsed_a0h_bytes, list) and len(parsed_a0h_bytes) > 256:
        # 分离前256字节给A0h，剩余给A2h
        a0h_part = parsed_a0h_bytes[:256]
        a2h_part = parsed_a0h_bytes[256:]
        
        # 更新A0h输入框
        formatted_a0h = format_hex_bytes(a0h_part)
        input_text.delete("1.0", tk.END)
        input_text.insert("1.0", formatted_a0h)
        parsed_a0h_bytes = a0h_part
        
        # 更新A2h输入框（替换原有内容）
        if a2h_part:
            formatted_a2h = format_hex_bytes(a2h_part)
            input_a2h_text.delete("1.0", tk.END)
            input_a2h_text.insert("1.0", formatted_a2h)
            parsed_a2h_bytes = a2h_part
    
    # 如果成功解析出数据，则格式化显示
    if parsed_a0h_bytes:
        # 将解析出的字节重新格式化为标准显示格式
        formatted_parts = []
        for i, byte_val in enumerate(parsed_a0h_bytes):
            formatted_parts.append(f"{byte_val:02X}")
            # 每16个字节换行
            if (i + 1) % 16 == 0 and (i + 1) < len(parsed_a0h_bytes):
                formatted_parts.append('\n')
            elif (i + 1) < len(parsed_a0h_bytes):
                formatted_parts.append(' ')
        
        formatted_string = "".join(formatted_parts)
        input_text.delete("1.0", tk.END)
        input_text.insert("1.0", formatted_string)
    
    if parsed_a2h_bytes:
        # 将解析出的字节重新格式化为标准显示格式
        formatted_parts_a2h = []
        for i, byte_val in enumerate(parsed_a2h_bytes):
            formatted_parts_a2h.append(f"{byte_val:02X}")
            # 每16个字节换行
            if (i + 1) % 16 == 0 and (i + 1) < len(parsed_a2h_bytes):
                formatted_parts_a2h.append('\n')
            elif (i + 1) < len(parsed_a2h_bytes):
                formatted_parts_a2h.append(' ')
        
        formatted_string_a2h = "".join(formatted_parts_a2h)
        input_a2h_text.delete("1.0", tk.END)
        input_a2h_text.insert("1.0", formatted_string_a2h)

    global bytes_data # Declare bytes_data as global for modification
    global addr_map # Declare addr_map as global for modification
    addr_map.clear() # Clear address map for new parsing

    a0h_parsed_len = len(parsed_a0h_bytes)
    a2h_parsed_len = len(parsed_a2h_bytes)

    # A0h interpretation requires at least 128 bytes for core fields, but its page is 256 bytes.
    should_interpret_a0h = (a0h_parsed_len >= 128) 
    # A2h interpretation requires 256 bytes as per Table 3.1a
    should_interpret_a2h = (a2h_parsed_len >= 256) 

    # Initialize full data buffers with zeros for 256 bytes each page
    full_a0h_data = [0x00] * 256
    full_a2h_data = [0x00] * 256

    result = []

    # Handle A0h section interpretation
    result.append("[A0h Section - Static Info (Overall Addresses 0-255)]\n") # A0h page is 256 bytes
    if should_interpret_a0h:
        # Copy parsed bytes up to 256 or actual length, whichever is smaller
        full_a0h_data[:min(a0h_parsed_len, 256)] = parsed_a0h_bytes[:min(a0h_parsed_len, 256)]
        
        # Each field includes its name, global address, and decoded value
        # A0h bytes 0-127
        addr_map["Identifier"] = 0
        result.append(f"Identifier (0): {full_a0h_data[0]:02X}")
        addr_map["Ext Identifier"] = 1
        result.append(f"Ext Identifier (1): {full_a0h_data[1]:02X}")
        addr_map["Connector"] = 2
        result.append(f"Connector (2): {full_a0h_data[2]:02X}")
        result.append(f"Transceiver (3-10): {' '.join(f'{b:02X}' for b in full_a0h_data[3:11])}")
        addr_map["Encoding"] = 11
        result.append(f"Encoding (11): {full_a0h_data[11]:02X}")
        addr_map["BR Nominal"] = 12
        result.append(f"BR Nominal (12): {full_a0h_data[12] * 100} Mbps")
        result.append(f"Rate Identifier (13): {full_a0h_data[13]:02X}")
        result.append(f"Length (SMF, km) (14): {full_a0h_data[14]} km")
        result.append(f"Length (SMF) (15): {full_a0h_data[15]} * 100m")
        result.append(f"Length (50µm) (16): {full_a0h_data[16]} * 10m")
        result.append(f"Length (62.5µm) (17): {full_a0h_data[17]} * 10m")
        result.append(f"Length (Copper) (18): {full_a0h_data[18]} m")
        result.append(f"Length (OM3) (19): {full_a0h_data[19]} * 10m")

        result.append(f"Vendor Name (20-35): {get_ascii(full_a0h_data, 20, 36)}")
        result.append(f"No meaning (36): Unallocated")
        result.append(f"Vendor OUI (37-39): {'-'.join(f'{b:02X}' for b in full_a0h_data[37:40])}")
        result.append(f"Vendor PN (40-55): {get_ascii(full_a0h_data, 40, 56)}")
        result.append(f"Vendor Rev (56-59): {get_ascii(full_a0h_data, 56, 60)}")
        addr_map["Wavelength"] = 60
        result.append(f"Wavelength (60-61): {get_u16(full_a0h_data, 60)} nm")
        result.append(f"No meaning (62): Unallocated")
        addr_map["CC_BASE"] = 63
        result.append(f"CC_BASE (63): {full_a0h_data[63]:02X}")
        addr_map["Options"] = 64
        result.append(f"Options (64-65): {full_a0h_data[64]:02X} {full_a0h_data[65]:02X}")
        result.append(f"BR Max (66): {full_a0h_data[66]}0 Mbps")
        result.append(f"BR Min (67): {full_a0h_data[67]}0 Mbps")
        result.append(f"Vendor SN (68-83): {get_ascii(full_a0h_data, 68, 84)}")
        result.append(f"Date Code (84-91): {get_ascii(full_a0h_data, 84, 92)}")
        addr_map["Diag Monitoring Type"] = 92
        result.append(f"Diag Monitoring Type (92): {full_a0h_data[92]:02X}")
        addr_map["Enhanced Options"] = 93
        result.append(f"Enhanced Options (93): {full_a0h_data[93]:02X}")
        addr_map["SFF-8472 Compliance"] = 94
        result.append(f"SFF-8472 Compliance (94): {full_a0h_data[94]:02X}")

        # Calculate Checksum for A0h:64-94
        checksum_a0h_64_94 = 0
        for i in range(64, 95): # Sum bytes 64 through 94 (exclusive of 95)
            if i < len(full_a0h_data):
                checksum_a0h_64_94 = (checksum_a0h_64_94 + full_a0h_data[i]) & 0xFF # Keep only lower 8 bits

        # CC_EXT (relative 95)
        cc_ext_value = full_a0h_data[95] if 95 < len(full_a0h_data) else "N/A"
        
        checksum_status_a0h = "Checksum Failed"
        if isinstance(cc_ext_value, int) and cc_ext_value == checksum_a0h_64_94:
            checksum_status_a0h = "Checksum Correct"

        addr_map["CC_EXT"] = 95
        result.append(f"CC_EXT (95): {checksum_status_a0h}. Byte 95 Value: 0x{cc_ext_value:02X} Sum of byte 64-94: 0x{checksum_a0h_64_94:02X}")
        
        extracted_decimal_bytes  = full_a0h_data[96:128]
        byte_sequence = bytes(extracted_decimal_bytes)
        vendor_specific_eeprom_string = byte_sequence.decode('ascii', errors='replace')
        result.append(f"Vendor Specific (96-127): Vendor Specific EEPROM\nVendor Specific in ASCII: {vendor_specific_eeprom_string}")
        
        # A0h bytes 128-255 are reserved for SFF-8079 - REMOVED RAW BYTE DISPLAY
        result.append(f"Reserved (128-255): Reserved for SFF-8079")

    else:
        result.append(f"    (A0h section not interpreted: {a0h_parsed_len} bytes found, 128 bytes required for interpretation)")

    # Handle A2h section interpretation based on Table 3.1a
    # These global addresses are 256-511, corresponding to A2h page bytes 0-255
    result.append("\n\n[A2h Section - Diagnostic Monitoring]\n") 
    if should_interpret_a2h:
        # Copy parsed bytes into full_a2h_data, which represents A2h addresses 0-255
        full_a2h_data[:min(a2h_parsed_len, 256)] = parsed_a2h_bytes[:min(a2h_parsed_len, 256)]
        
        # Diagnostics: Data Fields – Address A2h (relative addresses 0-255 within A2h page)
        # For display in output, use the relative A2h offset directly.
        
        # A/W Thresholds (relative 0-39) - Interpreted based on Table 3.15
        result.append(f"A/W Thresholds (A2h:0-39):")
        
        # Temperature thresholds (signed, 1/256 degrees Celsius per LSB)
        temp_high_alarm = get_s16(full_a2h_data, 0)
        result.append(f"  Temp High Alarm (A2h:0-1): {temp_high_alarm / 256.0:.2f} C" if temp_high_alarm is not None else "  Temp High Alarm (A2h:0-1): N/A")
        
        temp_low_alarm = get_s16(full_a2h_data, 2)
        result.append(f"  Temp Low Alarm (A2h:2-3): {temp_low_alarm / 256.0:.2f} C" if temp_low_alarm is not None else "  Temp Low Alarm (A2h:2-3): N/A")
        
        temp_high_warning = get_s16(full_a2h_data, 4)
        result.append(f"  Temp High Warning (A2h:4-5): {temp_high_warning / 256.0:.2f} C" if temp_high_warning is not None else "  Temp High Warning (A2h:4-5): N/A")
        
        temp_low_warning = get_s16(full_a2h_data, 6)
        result.append(f"  Temp Low Warning (A2h:6-7): {temp_low_warning / 256.0:.2f} C" if temp_low_warning is not None else "  Temp Low Warning (A2h:6-7): N/A")

        # Voltage thresholds (unsigned, 0.1 mV per LSB)
        voltage_high_alarm = get_u16(full_a2h_data, 8)
        result.append(f"  Voltage High Alarm (A2h:8-9): {voltage_high_alarm * 0.1:.2f} mV" if voltage_high_alarm is not None else "  Voltage High Alarm (A2h:8-9): N/A")
        
        voltage_low_alarm = get_u16(full_a2h_data, 10)
        result.append(f"  Voltage Low Alarm (A2h:10-11): {voltage_low_alarm * 0.1:.2f} mV" if voltage_low_alarm is not None else "  Voltage Low Alarm (A2h:10-11): N/A")
        
        voltage_high_warning = get_u16(full_a2h_data, 12)
        result.append(f"  Voltage High Warning (A2h:12-13): {voltage_high_warning * 0.1:.2f} mV" if voltage_high_warning is not None else "  Voltage High Warning (A2h:12-13): N/A")
        
        voltage_low_warning = get_u16(full_a2h_data, 14)
        result.append(f"  Voltage Low Warning (A2h:14-15): {voltage_low_warning * 0.1:.2f} mV" if voltage_low_warning is not None else "  Voltage Low Warning (A2h:14-15): N/A")

        # Bias thresholds (unsigned, 2 uA per LSB)
        bias_high_alarm = get_u16(full_a2h_data, 16)
        result.append(f"  Bias High Alarm (A2h:16-17): {bias_high_alarm * 2:.2f} uA" if bias_high_alarm is not None else "  Bias High Alarm (A2h:16-17): N/A")
        
        bias_low_alarm = get_u16(full_a2h_data, 18)
        result.append(f"  Bias Low Alarm (A2h:18-19): {bias_low_alarm * 2:.2f} uA" if bias_low_alarm is not None else "  Bias Low Alarm (A2h:18-19): N/A")
        
        bias_high_warning = get_u16(full_a2h_data, 20)
        result.append(f"  Bias High Warning (A2h:20-21): {bias_high_warning * 2:.2f} uA" if bias_high_warning is not None else "  Bias High Warning (A2h:20-21): N/A")
        
        bias_low_warning = get_u16(full_a2h_data, 22)
        result.append(f"  Bias Low Warning (A2h:22-23): {bias_low_warning * 2:.2f} uA" if bias_low_warning is not None else "  Bias Low Warning (A2h:22-23): N/A")

        # TX Power thresholds (unsigned, 0.1 uW per LSB, convert to dBm)
        tx_power_high_alarm_raw = get_u16(full_a2h_data, 24)
        if tx_power_high_alarm_raw is not None and tx_power_high_alarm_raw > 0:
            tx_power_high_alarm_dbm = 10 * math.log10(tx_power_high_alarm_raw * 0.1 / 1000.0)
            result.append(f"  TX Power High Alarm (A2h:24-25): {tx_power_high_alarm_dbm:.2f} dBm")
        else:
            result.append(f"  TX Power High Alarm (A2h:24-25): -Inf dBm" if tx_power_high_alarm_raw == 0 else "  TX Power High Alarm (A2h:24-25): N/A")
        
        tx_power_low_alarm_raw = get_u16(full_a2h_data, 26)
        if tx_power_low_alarm_raw is not None and tx_power_low_alarm_raw > 0:
            tx_power_low_alarm_dbm = 10 * math.log10(tx_power_low_alarm_raw * 0.1 / 1000.0)
            result.append(f"  TX Power Low Alarm (A2h:26-27): {tx_power_low_alarm_dbm:.2f} dBm")
        else:
            result.append(f"  TX Power Low Alarm (A2h:26-27): -Inf dBm" if tx_power_low_alarm_raw == 0 else "  TX Power Low Alarm (A2h:26-27): N/A")
        
        tx_power_high_warning_raw = get_u16(full_a2h_data, 28)
        if tx_power_high_warning_raw is not None and tx_power_high_warning_raw > 0:
            tx_power_high_warning_dbm = 10 * math.log10(tx_power_high_warning_raw * 0.1 / 1000.0)
            result.append(f"  TX Power High Warning (A2h:28-29): {tx_power_high_warning_dbm:.2f} dBm")
        else:
            result.append(f"  TX Power High Warning (A2h:28-29): -Inf dBm" if tx_power_high_warning_raw == 0 else "  TX Power High Warning (A2h:28-29): N/A")
        
        tx_power_low_warning_raw = get_u16(full_a2h_data, 30)
        if tx_power_low_warning_raw is not None and tx_power_low_warning_raw > 0:
            tx_power_low_warning_dbm = 10 * math.log10(tx_power_low_warning_raw * 0.1 / 1000.0)
            result.append(f"  TX Power Low Warning (A2h:30-31): {tx_power_low_warning_dbm:.2f} dBm")
        else:
            result.append(f"  TX Power Low Warning (A2h:30-31): -Inf dBm" if tx_power_low_warning_raw == 0 else "  TX Power Low Warning (A2h:30-31): N/A")

        # RX Power thresholds (unsigned, 0.1 uW per LSB, convert to dBm)
        rx_power_high_alarm_raw = get_u16(full_a2h_data, 32)
        if rx_power_high_alarm_raw is not None and rx_power_high_alarm_raw > 0:
            rx_power_high_alarm_dbm = 10 * math.log10(rx_power_high_alarm_raw * 0.1 / 1000.0)
            result.append(f"  RX Power High Alarm (A2h:32-33): {rx_power_high_alarm_dbm:.2f} dBm")
        else:
            result.append(f"  RX Power High Alarm (A2h:32-33): -Inf dBm" if rx_power_high_alarm_raw == 0 else "  RX Power High Alarm (A2h:32-33): N/A")
        
        rx_power_low_alarm_raw = get_u16(full_a2h_data, 34)
        if rx_power_low_alarm_raw is not None and rx_power_low_alarm_raw > 0:
            rx_power_low_alarm_dbm = 10 * math.log10(rx_power_low_alarm_raw * 0.1 / 1000.0)
            result.append(f"  RX Power Low Alarm (A2h:34-35): {rx_power_low_alarm_dbm:.2f} dBm")
        else:
            result.append(f"  RX Power Low Alarm (A2h:34-35): -Inf dBm" if rx_power_low_alarm_raw == 0 else "  RX Power Low Alarm (A2h:34-35): N/A")
        
        rx_power_high_warning_raw = get_u16(full_a2h_data, 36)
        if rx_power_high_warning_raw is not None and rx_power_high_warning_raw > 0:
            rx_power_high_warning_dbm = 10 * math.log10(rx_power_high_warning_raw * 0.1 / 1000.0)
            result.append(f"  RX Power High Warning (A2h:36-37): {rx_power_high_warning_dbm:.2f} dBm")
        else:
            result.append(f"  RX Power High Warning (A2h:36-37): -Inf dBm" if rx_power_high_warning_raw == 0 else "  RX Power High Warning (A2h:36-37): N/A")
        
        rx_power_low_warning_raw = get_u16(full_a2h_data, 38)
        if rx_power_low_warning_raw is not None and rx_power_low_warning_raw > 0:
            rx_power_low_warning_dbm = 10 * math.log10(rx_power_low_warning_raw * 0.1 / 1000.0)
            result.append(f"  RX Power Low Warning (A2h:38-39): {rx_power_low_warning_dbm:.2f} dBm")
        else:
            result.append(f"  RX Power Low Warning (A2h:38-39): -Inf dBm" if rx_power_low_warning_raw == 0 else "  RX Power Low Warning (A2h:38-39): N/A")



        # Unallocated (relative 40-55)
        result.append(f"\nUnallocated (A2h:40-55): Unallocated")
        
        # Ext Cal Constants (relative 56-91) - Interpreted based on Table 3.16
        result.append(f"\nExt Cal Constants (A2h:56-91):")
        rx_pwr_4 = get_float32(full_a2h_data, 56)
        result.append(f"  Rx_PWR(4) (A2h:56-59): {rx_pwr_4:.4e}" if rx_pwr_4 is not None else "  Rx_PWR(4) (A2h:56-59): N/A")
        
        rx_pwr_3 = get_float32(full_a2h_data, 60)
        result.append(f"  Rx_PWR(3) (A2h:60-63): {rx_pwr_3:.4e}" if rx_pwr_3 is not None else "  Rx_PWR(3) (A2h:60-63): N/A")
        
        rx_pwr_2 = get_float32(full_a2h_data, 64)
        result.append(f"  Rx_PWR(2) (A2h:64-67): {rx_pwr_2:.4e}" if rx_pwr_2 is not None else "  Rx_PWR(2) (A2h:64-67): N/A")
        
        rx_pwr_1 = get_float32(full_a2h_data, 68)
        result.append(f"  Rx_PWR(1) (A2h:68-71): {rx_pwr_1:.4e}" if rx_pwr_1 is not None else "  Rx_PWR(1) (A2h:68-71): N/A")
        
        rx_pwr_0 = get_float32(full_a2h_data, 72)
        result.append(f"  Rx_PWR(0) (A2h:72-75): {rx_pwr_0:.4e}" if rx_pwr_0 is not None else "  Rx_PWR(0) (A2h:72-75): N/A")

        tx_i_slope = get_u16(full_a2h_data, 76)
        result.append(f"  Tx_I(Slope) (A2h:76-77): {tx_i_slope}" if tx_i_slope is not None else "  Tx_I(Slope) (A2h:76-77): N/A")
        
        tx_i_offset = get_s16(full_a2h_data, 78)
        result.append(f"  Tx_I(Offset) (A2h:78-79): {tx_i_offset}" if tx_i_offset is not None else "  Tx_I(Offset) (A2h:78-79): N/A")

        tx_pwr_slope = get_u16(full_a2h_data, 80)
        result.append(f"  Tx_PWR(Slope) (A2h:80-81): {tx_pwr_slope}" if tx_pwr_slope is not None else "  Tx_PWR(Slope) (A2h:80-81): N/A")
        
        tx_pwr_offset = get_s16(full_a2h_data, 82)
        result.append(f"  Tx_PWR(Offset) (A2h:82-83): {tx_pwr_offset}" if tx_pwr_offset is not None else "  Tx_PWR(Offset) (A2h:82-83): N/A")

        t_slope = get_u16(full_a2h_data, 84)
        result.append(f"  T (Slope) (A2h:84-85): {t_slope}" if t_slope is not None else "  T (Slope) (A2h:84-85): N/A")
        
        t_offset = get_s16(full_a2h_data, 86)
        result.append(f"  T (Offset) (A2h:86-87): {t_offset}" if t_offset is not None else "  T (Offset) (A2h:86-87): N/A")

        v_slope = get_u16(full_a2h_data, 88)
        result.append(f"  V (Slope) (A2h:88-89): {v_slope}" if v_slope is not None else "  V (Slope) (A2h:88-89): N/A")
        
        v_offset = get_s16(full_a2h_data, 90)
        result.append(f"  V (Offset) (A2h:90-91): {v_offset}" if v_offset is not None else "  V (Offset) (A2h:90-91): N/A")

        # Unallocated (relative 92-94)
        result.append(f"\nUnallocated (A2h:92-94): Unallocated")
        
        # Calculate Checksum for A2h:0-94
        checksum_a2h_0_94 = 0
        for i in range(95): # Sum bytes 0 through 94
            if i < len(full_a2h_data):
                checksum_a2h_0_94 = (checksum_a2h_0_94 + full_a2h_data[i]) & 0xFF # Keep only lower 8 bits

        # CC_DMI (relative 95)
        cc_dmi_value = full_a2h_data[95] if 95 < len(full_a2h_data) else "N/A"
        
        checksum_status = "Checksum Error"
        if isinstance(cc_dmi_value, int) and cc_dmi_value == checksum_a2h_0_94:
            checksum_status = "Checksum Correct"

        addr_map["CC_DMI"] = 256 + 95 # Map global address
        result.append(f"\nCC_DMI (A2h:95): Check sum for A2h Byte 0-94. {checksum_status}. Byte 95 Value: 0x{cc_dmi_value:02X} Sum of byte 0-94: 0x{checksum_a2h_0_94:02X})")
	   
        # Diagnostics (relative 96-105) - Interpreted based on Table 3.17
        result.append(f"\nDiagnostics (A2h:96-105):")
        
        # Temperature (signed, 1/256 degrees Celsius per LSB)
        mod_temp = get_s16(full_a2h_data, 96)
        result.append(f"  Temperature (A2h:96-97): {mod_temp / 256.0:.2f} C" if mod_temp is not None else "  Temperature (A2h:96-97): N/A")
        
        # Vcc (unsigned, 0.1 mV per LSB)
        mod_vcc = get_u16(full_a2h_data, 98)
        result.append(f"  Vcc (A2h:98-99): {mod_vcc /10000:.4f} V" if mod_vcc is not None else "  Vcc (A2h:98-99): N/A")
        
        # TX Bias Current (unsigned, 2 uA per LSB)
        tx_bias = get_u16(full_a2h_data, 100)
        result.append(f"  TX Bias (A2h:100-101): {tx_bias * 2/1000:.4f} mA" if tx_bias is not None else "  TX Bias (A2h:100-101): N/A")
        
        # TX Power (unsigned, 0.1 uW per LSB, convert to dBm)
        tx_power_raw = get_u16(full_a2h_data, 102)
        if tx_power_raw is not None and tx_power_raw > 0:
            tx_power_mw = tx_power_raw /10000  # 原始单位是 0.1 µW
            tx_power_dbm = 10 * math.log10(tx_power_mw)
            #result.append(f"  TX Power (A2h:102-103): {tx_power_dbm:.2f} dBm")
            result.append(f"  TX Power (A2h:102-103): {tx_power_mw:.4f} mW ({tx_power_dbm:.2f} dBm)")
        else:
            result.append(f"  TX Power (A2h:102-103): -Inf dBm" if tx_power_raw == 0 else "  TX Power (A2h:102-103): N/A")
        
        # RX Power (unsigned, 0.1 uW per LSB, convert to dBm)
        rx_power_raw = get_u16(full_a2h_data, 104)
        if rx_power_raw is not None and rx_power_raw > 0:
            rx_power_mw = rx_power_raw /10000
            rx_power_dbm = 10 * math.log10(rx_power_mw)
            result.append(f"  RX Power (A2h:104-105): {rx_power_mw:.4f}mW ({rx_power_dbm:.2f} dBm)")
        else:
            result.append(f"  RX Power (A2h:104-105): -Inf dBm" if rx_power_raw == 0 else "  RX Power (A2h:104-105): N/A")


        # Unallocated (relative 106-109)
        result.append(f"\nUnallocated (A2h:106-109): Reserved for future diagnostic definitions")
        
        # Status/Control (relative 110) - Interpreted based on Table 3.17
        result.append(f"\nStatus/Control (A2h:110):")
        status_control_byte = full_a2h_data[110] if 110 < len(full_a2h_data) else None
        if status_control_byte is not None:
            result.append(f"  (A2h:110) Byte 110 Value: 0x{status_control_byte:02X} ({format_binary(status_control_byte)})")
            # Bit 7: TX Disable State
            result.append(f"  (A2h:110) Bit 7 (TX Disable State): {'1 (TX Disabled)' if (status_control_byte >> 7) & 1 else '0 (TX Enabled)'}")
            # Bit 6: Soft TX Disable Select
            result.append(f"  (A2h:110) Bit 6 (Soft TX Disable Select): {'1 (Software Disable)' if (status_control_byte >> 6) & 1 else '0 (Software Enable)'}")
            # Bit 5: RS(1) State
            result.append(f"  (A2h:110) Bit 5 (RS(1) State): {'1 (High)' if (status_control_byte >> 5) & 1 else '0 (Low)'}")
            # Bit 4: Rate_Select State [aka. “RS(0)”]
            result.append(f"  (A2h:110) Bit 4 (Rate_Select State): {'1 (High)' if (status_control_byte >> 4) & 1 else '0 (Low)'}")
            # Bit 3: Soft Rate_Select Select [aka. “RS(0)”]
            result.append(f"  (A2h:110) Bit 3 (Soft Rate_Select Select): {'1 (Full Bandwidth)' if (status_control_byte >> 3) & 1 else '0 (Normal Bandwidth)'}")
            # Bit 2: TX Fault State
            result.append(f"  (A2h:110) Bit 2 (TX Fault State): {'1 (Fault Detected)' if (status_control_byte >> 2) & 1 else '0 (No Fault)'}")
            # Bit 1: Rx_LOS State
            result.append(f"  (A2h:110) Bit 1 (Rx_LOS State): {'1 (LOS Detected)' if (status_control_byte >> 1) & 1 else '0 (No LOS)'}")
            # Bit 0: Data_Ready_Bar State
            result.append(f"  (A2h:110) Bit 0 (Data_Ready_Bar State): {'1 (Not Ready)' if (status_control_byte >> 0) & 1 else '0 (Data Ready)'}")
        else:
            result.append(f"\nStatus/Control (A2h:110): N/A (Insufficient Data)")

        # Reserved (relative 111)
        result.append(f"\nReserved (A2h:111): Reserved for SFF-8079")
        
        # Alarm Flags (relative 112-113) - New section
        result.append(f"\nAlarm Flags (A2h:112-113):")
        if 112 < len(full_a2h_data):
            byte_112_val = full_a2h_data[112]
            result.append(f"  (A2h:112) (0x{byte_112_val:02X}):")
            result.append(f"  (A2h:112){get_bit_status(byte_112_val, 7, 'Temp High Alarm')}")
            result.append(f"  (A2h:112){get_bit_status(byte_112_val, 6, 'Temp Low Alarm')}")
            result.append(f"  (A2h:112){get_bit_status(byte_112_val, 5, 'Vcc High Alarm')}")
            result.append(f"  (A2h:112){get_bit_status(byte_112_val, 4, 'Vcc Low Alarm')}")
            result.append(f"  (A2h:112){get_bit_status(byte_112_val, 3, 'TX Bias High Alarm')}")
            result.append(f"  (A2h:112){get_bit_status(byte_112_val, 2, 'TX Bias Low Alarm')}")
            result.append(f"  (A2h:112){get_bit_status(byte_112_val, 1, 'TX Power High Alarm')}")
            result.append(f"  (A2h:112){get_bit_status(byte_112_val, 0, 'TX Power Low Alarm')}")
        else:
            result.append(f"  (A2h:112): N/A (data not available)")

        if 113 < len(full_a2h_data):
            byte_113_val = full_a2h_data[113]
            result.append(f"  (A2h:113)(0x{byte_113_val:02X}):")
            result.append(f"  (A2h:113){get_bit_status(byte_113_val, 7, 'RX Power High Alarm')}")
            result.append(f"  (A2h:113){get_bit_status(byte_113_val, 6, 'RX Power Low Alarm')}")
            result.append(f"  (A2h:113)5-0: Reserved Alarm (Value: 0x{byte_113_val & 0x3F:02X})") # Mask for bits 5-0
        else:
            result.append(f"  (A2h:113): N/A (data not available)")
     
        # Unallocated (relative 114-115) - New section
        result.append(f"\nUnallocated (A2h:114-115): Unallocated")

        # Warning Flags (relative 116-117) - New section
        result.append(f"\nWarning Flags (A2h:116-117):")
        if 116 < len(full_a2h_data):
            byte_116_val = full_a2h_data[116]
            result.append(f"  (A2h:116)(0x{byte_116_val:02X}):")
            result.append(f"  (A2h:116){get_bit_status(byte_116_val, 7, 'Temp High Warning')}")
            result.append(f"  (A2h:116){get_bit_status(byte_116_val, 6, 'Temp Low Warning')}")
            result.append(f"  (A2h:116){get_bit_status(byte_116_val, 5, 'Vcc High Warning')}")
            result.append(f"  (A2h:116){get_bit_status(byte_116_val, 4, 'Vcc Low Warning')}")
            result.append(f"  (A2h:116){get_bit_status(byte_116_val, 3, 'TX Bias High Warning')}")
            result.append(f"  (A2h:116){get_bit_status(byte_116_val, 2, 'TX Bias Low Warning')}")
            result.append(f"  (A2h:116){get_bit_status(byte_116_val, 1, 'TX Power High Warning')}")
            result.append(f"  (A2h:116){get_bit_status(byte_116_val, 0, 'TX Power Low Warning')}")
        else:
            result.append(f"  (A2h:116): N/A (data not available)")

        if 117 < len(full_a2h_data):
            byte_117_val = full_a2h_data[117]
            result.append(f"  (A2h:117)(0x{byte_117_val:02X}):")
            result.append(f"  (A2h:117){get_bit_status(byte_117_val, 7, 'RX Power High Warning')}")
            result.append(f"  (A2h:117){get_bit_status(byte_117_val, 6, 'RX Power Low Warning')}")
            result.append(f"  (A2h:117)Bit 5-0: Reserved Warning (Value: 0x{byte_117_val & 0x3F:02X})") # Mask for bits 5-0
        else:
            result.append(f"  (A2h:117): N/A (data not available)")
        
        
        # Ext Status/Control (relative 118-119) - Interpreted based on Table 3.18a
        result.append(f"\nExt Status/Control (A2h:118-119):")
        ext_status_control_byte = full_a2h_data[118] if 118 < len(full_a2h_data) else None
        if ext_status_control_byte is not None:
            result.append(f"  (A2h:118) Byte 118 Value: 0x{ext_status_control_byte:02X} ({format_binary(ext_status_control_byte)})")
            result.append(f"  (A2h:118)Bits 7-4: Reserved (Value: 0x{(ext_status_control_byte >> 4) & 0xF:01X})")
            result.append(f"  (A2h:118){get_bit_status(ext_status_control_byte, 3, 'Soft RS(1) Select')}: {'1 (Full Speed Tx)' if (ext_status_control_byte >> 3) & 1 else '0 (Normal Speed Tx)'}")
            result.append(f"  (A2h:118)Bit 2: Reserved ({'1' if (ext_status_control_byte >> 2) & 1 else '0'})")
            power_level_state = 'Power Level 2 (1.5W max)' if (ext_status_control_byte >> 1) & 1 else 'Power Level 1 (1.0W max)'
            result.append(f"  (A2h:118){get_bit_status(ext_status_control_byte, 1, 'Power Level Operation State')}: {power_level_state}")
            power_level_select = 'Enables Power Level 2 (1.5W max)' if (ext_status_control_byte >> 0) & 1 else 'Disables Power Level 2 (1.0W max)'
            result.append(f"  (A2h:118){get_bit_status(ext_status_control_byte, 0, 'Power Level Select')}: {power_level_select}")
        else:
            result.append(f"  (A2h:118): N/A (Insufficient Data)")

        result.append(f"  (A2h:119)7-0: Unallocated")
        
        # Vendor Specific (relative 120-127)
        extracted_decimal_bytes  = full_a2h_data[120:128]
        byte_sequence = bytes(extracted_decimal_bytes)
        vendor_specific_eeprom_string = byte_sequence.decode('ascii', errors='replace')
        #result.append(f"Vendor Specific (96-127): Vendor Specific EEPROM\nVendor Specific in ASCII: {vendor_specific_eeprom_string}")
        result.append(f"\nVendor Specific (A2h:120-127): Vendor specific memory addresses (see Table 3.19)\nVendor Specific in ASCII (A2h:120-127):  {vendor_specific_eeprom_string}")
        
        # User EEPROM (relative 128-247)
        extracted_decimal_bytes  = full_a2h_data[128:248]
        byte_sequence = bytes(extracted_decimal_bytes)
        vendor_specific_eeprom_string = byte_sequence.decode('ascii', errors='replace')
        result.append(f"\nUser EEPROM (A2h:128-247): User writable EEPROM (see Table 3.20)\nUser EEPROM in ASCII (A2h:128-247):  {vendor_specific_eeprom_string}")
        
        # Vendor Control (relative 248-255)
        extracted_decimal_bytes  = full_a2h_data[248:256]
        byte_sequence = bytes(extracted_decimal_bytes)
        vendor_specific_eeprom_string = byte_sequence.decode('ascii', errors='replace')
        result.append(f"\nVendor Control (A2h:248-255): Vendor specific control functions (see Table 3.21)\nVendor Control in ASCII (A2h:248-255):  {vendor_specific_eeprom_string}")


    else:
        result.append(f"    (A2h section not interpreted: {a2h_parsed_len} bytes found, 256 bytes required for interpretation)")

    # Combine the two sections for the global bytes_data.
    # This ensures bytes_data always has 512 elements (256 for A0h + 256 for A2h), even if not all were interpreted.
    bytes_data = full_a0h_data + full_a2h_data # Total 512 bytes for full SFP+ DDM

    # Update the decoded output text area
    output_text.config(state='normal')
    output_text.delete("1.0", tk.END)
    output_text.insert(tk.END, "\n".join(result))
    #output_text.config(state='disabled') # Keep it editable for copy/paste if desired

def update_bit_output_from_entries(*args):
    """
    Reads the values from the 8 individual bit entry boxes,
    constructs an 8-bit binary string, and updates the bit_output_text.
    """
    global _current_bit_addr, _current_bit_value

    if _current_bit_addr == -1 or not bytes_data:
        # No byte selected, or data not loaded, do nothing
        return

    new_binary_str = ""
    for i in range(8):
        bit_val = bit_entries[i].get().strip()
        if bit_val not in ['0', '1']:
            # If invalid input, reset to '0' and warn
            bit_entries[i].delete(0, tk.END)
            bit_entries[i].insert(0, '0')
            messagebox.showwarning("Invalid Input", "Bit values must be '0' or '1'. Resetting invalid bit.")
            return # Stop processing to prevent further errors
        new_binary_str += bit_val

    # Convert binary string to integer
    new_val = int(new_binary_str, 2)

    # Update the global current bit value
    _current_bit_value = new_val

    # 获取当前可见顶部的文本位置
    y_pos = bit_output_text.yview()[0] 

    #获取当前高亮内容的位置
    try:
        hl_start = bit_output_text.index("highlight.first")
        hl_end = bit_output_text.index("highlight.last")
        #selected_bin_str = bit_output_text.get(hl_start, hl_end)
    except tk.TclError:
        hl_start = hl_end = None
        #selected_bin_str = None

    # Update the first line of bit_output_text
    content = bit_output_text.get("1.0", tk.END)
    lines = content.splitlines()
    target_addr = _current_bit_addr
    # 构造新的行列表
    new_lines = []
    for line in lines:
        # 尝试匹配行中的地址
        m = re.search(r"(?i)(A2h)?\s*byte\s+(\d+):?", line)
        if m:
            a2h_flag = m.group(1)
            byte_num = int(m.group(2))
            addr = byte_num + 255 if a2h_flag else byte_num

            if addr == target_addr:
                # 匹配到了当前地址，进行替换
                # 替换 Binary 部分
                match = re.search(r"(.*Binary:\s*)([01]{8})(.*)", line)
                if match:
                    prefix = match.group(1)
                    suffix = match.group(3)

                    # 替换 HEX 部分
                    hex_val = f"0x{new_val:02X}"
                    hex_match = re.search(r"(HEX:\s*)(0x[0-9a-fA-F]{2})", prefix)
                    if hex_match:
                        prefix = prefix.replace(hex_match.group(2), hex_val)

                    # 构造新行
                    new_line = f"{prefix}{new_binary_str}{suffix}"
                    new_lines.append(new_line)
                    continue  # 该行处理完了，跳过到下一行
        # 非目标行或无法解析行，原样加入
        new_lines.append(line)

    # 更新文本框内容
    bit_output_text.delete("1.0", tk.END)
    bit_output_text.insert("1.0", "\n".join(new_lines))

    # 3. 恢复高亮（如果之前有选中内容）
    if hl_start and hl_end:
        bit_output_text.tag_add("highlight", hl_start, hl_end)

    # 恢复原来的可见位置（尽量滚动到原始可见行）
    bit_output_text.yview_moveto(y_pos)

def on_bit_entry_click(event):
    """
    Handles click event on individual bit entry boxes.
    Toggles the bit value (0 to 1, 1 to 0). If invalid, sets to 0.
    Then triggers update_bit_output_from_entries.
    """
    clicked_entry = event.widget
    current_value = clicked_entry.get().strip()
    
    new_value = '0'
    if current_value == '0':
        new_value = '1'
    elif current_value == '1':
        new_value = '0'
    # If it's anything else or empty, it defaults to '0' as per new_value initialization

    clicked_entry.delete(0, tk.END)
    clicked_entry.insert(0, new_value)
    
    # After changing the individual bit, update the main bit output and hex/binary display
    update_bit_output_from_entries()


def on_bit_output_click(event):
    """
    Handles click event on bit_output_text.
    If an 8-bit binary string is at cursor position, it highlights and populates the individual bit entry boxes.
    """
    try:
        # 清除旧的高亮
        bit_output_text.tag_remove("highlight", "1.0", tk.END)
        # Get the clicked position
        index = bit_output_text.index(f"@{event.x},{event.y}")
        # 使用 word start / word end 获取完整单词
        word_start = bit_output_text.index(f"{index} wordstart")
        word_end = bit_output_text.index(f"{index} wordend")
        word = bit_output_text.get(word_start, word_end)
        selected_text = word

        if re.fullmatch(r"[01]{8}", selected_text):
            # 高亮当前 binary 选中项
            bit_output_text.tag_add("highlight", word_start, word_end)
            for i in range(8):
                bit_entries[i].delete(0, tk.END)
                bit_entries[i].insert(0, selected_text[i])
            # 获取当前点击所在行
            line_index = index.split('.')[0]
            line_text = bit_output_text.get(f"{line_index}.0", f"{line_index}.end")

            # 尝试从行首提取地址
            m = re.search(r"(?i)(A2h)?\s*byte\s+(\d+):?", line_text)
            if m:
                a2h_flag = m.group(1)
                byte_num = int(m.group(2))
                if a2h_flag:
                    addr = 255 + byte_num
                else:
                    addr = byte_num
                global _current_bit_addr
                _current_bit_addr = addr
                print(f"Detected bit address: {_current_bit_addr}")
            else:
                print("Warning: Could not extract address from line.")
        else:
            # If not an 8-bit binary, clear individual bit entries
            for i in range(8):
                bit_entries[i].delete(0, tk.END)
                bit_entries[i].insert(0, '0') # Reset to default
    except Exception as e:
        print(f"Error in on_bit_output_click: {e}")


def on_cursor_click(event):
    # Clears previous highlights in ALL text areas
    output_text.tag_remove("highlight", "1.0", tk.END)
    input_text.tag_remove("highlight", "1.0", tk.END) # Clear A0h input highlight
    input_a2h_text.tag_remove("highlight", "1.0", tk.END) # Clear A2h input highlight
    
    # Always ensure bit_output_text is normal and apply_change_button is enabled
    bit_output_text.config(state='normal') 
    bit_output_text.delete("1.0", tk.END)
    apply_change_button.config(state='normal')

    # Gets the start and end indices of the clicked line in output_text
    cursor_index = output_text.index(f"@{event.x},{event.y}")
    line_start = cursor_index.split('.')[0] + ".0"
    line_end = cursor_index.split('.')[0] + ".end"

    # Adds highlight to the clicked line in output_text
    output_text.tag_add("highlight", line_start, line_end)
    output_text.update_idletasks() # Force update to ensure highlight is drawn

    # Parses register bit explanation and extracts address/range
    line_text = output_text.get(line_start, line_end)
    
    # NEW REGEX: Matches (Page:Addr) or (Addr) for single bytes
    match_single = re.search(r"\((\w+):(\d+)\)|\((\d+)\)", line_text)
        # NEW REGEX: Matches (Page:Start-End) or (Start-End) for ranges
    match_range = re.search(r"\((\w+):(?P<start_addr>\d+)-(?P<end_addr>\d+)\)|\((?P<start_addr_no_page>\d+)-(?P<end_addr_no_page>\d+)\)", line_text)

    global _current_bit_addr, _current_bit_value # Ensure these are treated as global

    start_addr_to_highlight = -1
    end_addr_to_highlight = -1
    
    # Check if the clicked line is an interpretation message or actual data
    if "not interpreted" in line_text:
        bit_output_text.insert(tk.END, "This section was not interpreted due to insufficient data.")
        _current_bit_addr = -1
        _current_bit_value = -1
        return # Do not proceed with highlighting or bit explanation for uninterpreted sections

    if match_range:
        # Case 1: Matched (Page:Start-End) format (e.g., A2h:0-39)
        if match_range.group(1): # If group 1 (page name) is not None
            page_name = match_range.group(1)
            displayed_start_addr = int(match_range.group('start_addr'))
            displayed_end_addr = int(match_range.group('end_addr'))
            if page_name == "A2h":
                start_addr_to_highlight = displayed_start_addr + 256
                end_addr_to_highlight = displayed_end_addr + 256
            else: # Assume A0h if page is explicitly given but not A2h, or if it's the A0h section
                start_addr_to_highlight = displayed_start_addr
                end_addr_to_highlight = displayed_end_addr
        # Case 2: Matched (Start-End) format (e.g., 3-10 for A0h)
        else:
            displayed_start_addr = int(match_range.group('start_addr_no_page'))
            displayed_end_addr = int(match_range.group('end_addr_no_page'))
            start_addr_to_highlight = displayed_start_addr
            end_addr_to_highlight = displayed_end_addr

        # Display explanations for all bytes in the range
        for current_addr in range(start_addr_to_highlight, end_addr_to_highlight + 1):
            if bytes_data and 0 <= current_addr < len(bytes_data):
                val = bytes_data[current_addr]
                bin_result = explain_bits(current_addr, val)
                bit_output_text.insert(tk.END, bin_result)
                if current_addr < end_addr_to_highlight:
                    bit_output_text.insert(tk.END, "\n-------------------------------\n") # Add separator
        
        _current_bit_addr = -1 # Indicate no single byte is selected for editing in multi-byte view
        _current_bit_value = -1 # Reset value

    elif match_single:
        # Case 1: Matched (Page:Addr) format (e.g., A2h:95)
        if match_single.group(1): # If group 1 (page name) is not None
            page_name = match_single.group(1)
            displayed_addr = int(match_single.group(2))
            if page_name == "A2h":
                start_addr_to_highlight = displayed_addr + 256 # Convert A2h relative to global
            else: # Assume A0h if page is explicitly given but not A2h, or if it's the A0h section
                start_addr_to_highlight = displayed_addr
        # Case 2: Matched (Addr) format (e.g., 0, 1, 2 for A0h)
        else:
            displayed_addr = int(match_single.group(3)) # Group 3 captures the address if no page is specified
            start_addr_to_highlight = displayed_addr # A0h addresses are global directly
            
        end_addr_to_highlight = start_addr_to_highlight
        _current_bit_addr = start_addr_to_highlight # Store the global address for editing

        if bytes_data and 0 <= _current_bit_addr < len(bytes_data):
            _current_bit_value = bytes_data[_current_bit_addr] # Store the current value
            val = bytes_data[_current_bit_addr]
            bin_result = explain_bits(_current_bit_addr, val)
            bit_output_text.insert(tk.END, bin_result) 

    else:
        # No specific byte/range found (e.g., clicked on blank line or section header)
        _current_bit_addr = -1
        _current_bit_value = -1


    # Common highlighting for input_text based on any valid selection
    if bytes_data and 0 <= start_addr_to_highlight < len(bytes_data):
        for current_addr in range(start_addr_to_highlight, end_addr_to_highlight + 1):
            if current_addr < len(bytes_data):
                # Determine which input text widget to highlight
                target_input_text = None
                relative_addr = current_addr
                if current_addr < 256: # A0h section (global 0-255)
                    target_input_text = input_text
                    # relative_addr = current_addr (already relative to A0h input)
                else: # A2h section (global 256-511)
                    target_input_text = input_a2h_text
                    relative_addr = current_addr - 256 # Adjust to 0-indexed for A2h input box

                line_in_input = relative_addr // 16
                byte_offset_in_line = relative_addr % 16
                
                # Get the actual line content from the target input widget
                actual_input_line_content = target_input_text.get(f"{line_in_input + 1}.0", f"{line_in_input + 1}.end").strip()
                
                hex_matches = list(re.finditer(r'[0-9a-fA-F]{2}', actual_input_line_content))

                if byte_offset_in_line < len(hex_matches):
                    match = hex_matches[byte_offset_in_line]
                    start_char_pos = match.start()
                    
                    start_idx = f"{line_in_input + 1}.{start_char_pos}"
                    end_idx = f"{line_in_input + 1}.{start_char_pos + 2}" # 2 chars for the hex value
                    target_input_text.tag_add("highlight", start_idx, end_idx)

def on_input_click(event):
    # Clear previous highlights in all text areas
    input_text.tag_remove("highlight", "1.0", tk.END)
    input_a2h_text.tag_remove("highlight", "1.0", tk.END)
    output_text.tag_remove("highlight", "1.0", tk.END)
    bit_output_text.config(state='normal') # Keep editable
    bit_output_text.delete("1.0", tk.END)
    
    selected_byte_addr = -1
    clicked_widget = event.widget

    # Determine which input widget was clicked and calculate the global address
    if clicked_widget == input_text:
        base_address = 0
    elif clicked_widget == input_a2h_text:
        base_address = 256
    else:
        return # Not an input text widget we care about

    # Get clicked Tkinter index (e.g., "1.5")
    tk_index = clicked_widget.index(f"@{event.x},{event.y}")
    line_num = int(tk_index.split('.')[0]) - 1 # 0-indexed line number
    char_in_line = int(tk_index.split('.')[1]) # 0-indexed char position in line

    # Retrieve the content of the clicked input widget
    raw_input_content = clicked_widget.get("1.0", tk.END)
    lines = raw_input_content.split('\n')

    current_byte_offset_in_widget = 0
    selected_input_start_tk_index = None
    selected_input_end_tk_index = None

    for i, line_content in enumerate(lines):
        if i == line_num: # This is the clicked line
            hex_matches = list(re.finditer(r'[0-9a-fA-F]{2}', line_content))

            for j, match in enumerate(hex_matches):
                start_pos_in_line_content = match.start()
                end_pos_in_line_content = match.end()
                
                if start_pos_in_line_content <= char_in_line < end_pos_in_line_content:
                    selected_byte_addr = base_address + current_byte_offset_in_widget + j
                    
                    selected_input_start_tk_index = f"{line_num + 1}.{start_pos_in_line_content}"
                    selected_input_end_tk_index = f"{line_num + 1}.{end_pos_in_line_content}"
                    break # Found the clicked byte, exit inner loop
        
        if selected_byte_addr != -1:
            break # Found the clicked byte, exit outer loop

        # Only count hex bytes to correctly calculate current_byte_offset_in_widget
        current_byte_offset_in_widget += len([x for x in line_content.replace("\n", " ").replace(",", " ").replace("0x", " ").strip().split() if len(x) == 2])


    if selected_byte_addr != -1 and bytes_data and 0 <= selected_byte_addr < len(bytes_data):
        # 1. Highlight in the clicked input_text
        if selected_input_start_tk_index and selected_input_end_tk_index:
            clicked_widget.tag_add("highlight", selected_input_start_tk_index, selected_input_end_tk_index)
            #clicked_widget.tag_config("selected_input", background="yellow", foreground="black")

        # 2. Highlight corresponding line in output_text
        output_lines = output_text.get("1.0", tk.END).split('\n')
        found = False
        for i, output_line in enumerate(output_lines):
            match_single_output = re.search(r"\((\w+):(\d+)\)|\((\d+)\)", output_line)
            match_range_output = re.search(r"\((\w+):(?P<start_addr>\d+)-(?P<end_addr>\d+)\)|\((?P<start_addr_no_page>\d+)-(?P<end_addr_no_page>\d+)\)", output_line)

            if match_single_output:
                if match_single_output.group(1):
                    page_name = match_single_output.group(1)
                    addr_relative = int(match_single_output.group(2))
                    addr_global = addr_relative + 256 if page_name == "A2h" else addr_relative
                else:
                    addr_relative = int(match_single_output.group(3))
                    addr_global = addr_relative

                if addr_global == selected_byte_addr:
                    output_text.tag_add("highlight", f"{i + 1}.0", f"{i + 1}.end")
                    output_text.update_idletasks()
                    output_text.see(f"{i + 1}.0")
                    found = True
                    break

            elif match_range_output:
                if match_range_output.group(1):
                    page_name = match_range_output.group(1)
                    start_relative = int(match_range_output.group('start_addr'))
                    end_relative = int(match_range_output.group('end_addr'))
                    start_global = start_relative + 256 if page_name == "A2h" else start_relative
                    end_global = end_relative + 256 if page_name == "A2h" else end_relative
                else:
                    start_relative = int(match_range_output.group('start_addr_no_page'))
                    end_relative = int(match_range_output.group('end_addr_no_page'))
                    start_global = start_relative
                    end_global = end_relative

                if start_global <= selected_byte_addr <= end_global:
                    byte_relative = selected_byte_addr - 256 if selected_byte_addr >= 256 else selected_byte_addr
                    for j in range(i + 1, len(output_lines)):
                        line = output_lines[j].strip()
                        if not line:
                            continue
                        if not output_lines[j].startswith("  "):
                            break
                        # 支持匹配该字节为高地址位的情况，例如 byte 1 属于 (A2h:0-1)
                        if re.search(rf"\(A2h:(\d+)-(\d+)\)", line):
                            m = re.search(rf"\(A2h:(\d+)-(\d+)\)", line)
                            low = int(m.group(1))
                            high = int(m.group(2))
                            if low <= byte_relative <= high:
                                output_text.tag_add("highlight", f"{j + 1}.0", f"{j + 1}.end")
                                output_text.update_idletasks()
                                output_text.see(f"{j + 1}.0")
                                found = True
                                break
                    if not found:
                        output_text.tag_add("highlight", f"{i + 1}.0", f"{i + 1}.end")
                        output_text.update_idletasks()
                        output_text.see(f"{i + 1}.0")
                        found = True
                    break


            
        # 3. Update bit explanation
        if selected_byte_addr < len(bytes_data):
            global _current_bit_addr, _current_bit_value
            _current_bit_addr = selected_byte_addr # Store the address
            _current_bit_value = bytes_data[selected_byte_addr] # Store the current value
            val = bytes_data[selected_byte_addr]
            bin_result = explain_bits(_current_bit_addr, val)
            bit_output_text.config(state='normal')
            bit_output_text.delete("1.0", tk.END)
            bit_output_text.insert(tk.END, bin_result)
            #bit_output_text.config(state='disabled') # Keep disabled if edited through input_text


def load_qr_image():
    """加载二维码图片"""
    try:
        image_path = resource_path("my_image.jpg")
        return Image.open(image_path)
    except Exception as e:
        print(f"无法加载图片: {e}")
        return None

def apply_changes():
    try:
        # 首先检查是否有8位二进制数被选中
        try:
            hl_start = bit_output_text.index("highlight.first")
            hl_end = bit_output_text.index("highlight.last")
        except tk.TclError:
            messagebox.showwarning("No Selection", "Please click an 8-bit binary field to highlight it first.")
            return
        
        selected_binary = bit_output_text.get(hl_start, hl_end).strip()
        
        if not re.fullmatch(r"[01]{8}", selected_binary):
            messagebox.showwarning("Invalid Binary", "Selected binary is not 8 bits.")
            return
        
        # 获取当前高亮的其他区域（用于后续恢复）
        try:
            sel_input_text_start = input_text.index("highlight.first")
            sel_input_text_end = input_text.index("highlight.last")
        except tk.TclError:
            sel_input_text_start = sel_input_text_end = None

        try:
            sel_input_a2h_text_start = input_a2h_text.index("highlight.first")
            sel_input_a2h_text_end = input_a2h_text.index("highlight.last")
        except tk.TclError:
            sel_input_a2h_text_start = sel_input_a2h_text_end = None

        try:
            sel_output_text_start = output_text.index("highlight.first")
            sel_output_text_end = output_text.index("highlight.last")
        except tk.TclError:
            sel_output_text_start = sel_output_text_end = None

        # Step 2: 获取所在行的完整文本
        line_index = hl_start.split('.')[0]
        line_text = bit_output_text.get(f"{line_index}.0", f"{line_index}.end")

        # Step 3: 判断 A0h/A2h + 提取 Byte 索引
        m = re.search(r"(?i)(A2h)?\s*Byte\s+(\d+):", line_text)
        if not m:
            messagebox.showwarning("Parse Error", "Cannot find Byte index in the selected line.")
            return

        is_a2h = bool(m.group(1))
        byte_index = int(m.group(2))
        hex_value = f"{int(selected_binary, 2):02X}"  # 不加 0x，因为控件中是裸 HEX（如 A4）

        # Step 4: 获取并拆分对应输入框的所有 hex 字节
        target_widget = input_a2h_text if is_a2h else input_text

        full_text = target_widget.get("1.0", tk.END).strip()
        hex_bytes = full_text.split()  # 以空格拆分成 byte 列表

        if byte_index >= len(hex_bytes):
            messagebox.showwarning("Byte Index Error", f"Byte {byte_index} is out of range.")
            return

        # Step 5: 替换对应 Byte
        hex_bytes[byte_index] = hex_value.upper()

        # Step 6: 重新格式化成 16 字节一行
        new_lines = []
        for i in range(0, len(hex_bytes), 16):
            line = ' '.join(hex_bytes[i:i+16])
            new_lines.append(line)

        # Step 7: 回写
        target_widget.config(state='normal')
        target_widget.delete("1.0", tk.END)
        target_widget.insert("1.0", '\n'.join(new_lines))
        #target_widget.config(state='disabled')

        # Step 8: 触发解析函数
        parse_registers()

        # 恢复 input_text 的 selected_input 标签
        if sel_input_text_start and sel_input_text_end:
            input_text.tag_add("highlight", sel_input_text_start, sel_input_text_end)

        # 恢复 input_a2h_text 的 selected_input 标签
        if sel_input_a2h_text_start and sel_input_a2h_text_end:
            input_a2h_text.tag_add("highlight", sel_input_a2h_text_start, sel_input_a2h_text_end)

        # 恢复 output_text 的 selected_output 标签（如果你有这个标签）
        if sel_output_text_start and sel_output_text_end:
            output_text.tag_add("highlight", sel_output_text_start, sel_output_text_end)

        # 恢复 bit_output_text 的 highlight_bin 标签
        if hl_start and hl_end:
            bit_output_text.tag_add("highlight", hl_start, hl_end)
        '''output_text.tag_config("highlight",  background="yellow", foreground="black")
        input_text.tag_config("selected_input", background="yellow", foreground="black") 
        input_a2h_text.tag_config("selected_input", background="yellow", foreground="black") 
        bit_output_text.tag_configure("highlight_bin", background="yellow")'''


    #except tk.TclError:
        #messagebox.showwarning("No Selection", "Please double-click an 8-bit binary field to highlight it.")
    except Exception as e:
        messagebox.showerror("Error", f"apply_changes failed:\n{e}")

def show_context_menu(event, text_widget):
    """显示右键菜单"""
    context_menu = tk.Menu(root, tearoff=0)
    context_menu.add_command(label="复制", command=lambda: copy_text(text_widget))
    context_menu.add_command(label="剪切", command=lambda: cut_text(text_widget))
    context_menu.add_command(label="粘贴", command=lambda: paste_text(text_widget))
    context_menu.add_separator()
    context_menu.add_command(label="全选", command=lambda: select_all_text(text_widget))
    context_menu.add_command(label="删除", command=lambda: delete_text(text_widget))
    
    try:
        context_menu.tk_popup(event.x_root, event.y_root)
    finally:
        context_menu.grab_release()

def copy_text(text_widget):
    """复制选中文本"""
    try:
        text_widget.clipboard_clear()
        text_widget.clipboard_append(text_widget.selection_get())
    except tk.TclError:
        pass

def cut_text(text_widget):
    """剪切选中文本"""
    try:
        text_widget.clipboard_clear()
        text_widget.clipboard_append(text_widget.selection_get())
        text_widget.delete(tk.SEL_FIRST, tk.SEL_LAST)
    except tk.TclError:
        pass

def paste_text(text_widget):
    """粘贴文本"""
    try:
        text_widget.insert(tk.INSERT, text_widget.clipboard_get())
    except tk.TclError:
        pass

def select_all_text(text_widget):
    """全选文本"""
    text_widget.tag_add(tk.SEL, "1.0", tk.END)
    text_widget.mark_set(tk.INSERT, "1.0")
    text_widget.see(tk.INSERT)

def delete_text(text_widget):
    """删除选中文本"""
    try:
        text_widget.delete(tk.SEL_FIRST, tk.SEL_LAST)
    except tk.TclError:
        pass

def show_about_window():
    top = tk.Toplevel(root)
    top.title("Donation")
    # 设置固定窗口大小
    win_width = 300
    win_height = 300

    # 获取主窗口的位置和尺寸
    root.update_idletasks()
    root_x = root.winfo_x()
    root_y = root.winfo_y()
    root_width = root.winfo_width()
    root_height = root.winfo_height()

    # 计算居中位置
    pos_x = root_x + (root_width - win_width) // 2
    pos_y = root_y + (root_height - win_height) // 2

    # 设置 Toplevel 窗口的大小和位置
    top.geometry(f"{win_width}x{win_height}+{pos_x}+{pos_y}")
    
    # 加载图片
    try:
        image = load_qr_image()
        if image:
            img_resized = image.resize((200, 200), Image.Resampling.LANCZOS)
            photo = ImageTk.PhotoImage(img_resized)

            # 显示图片
            label = tk.Label(top, image=photo)
            label.image = photo  # 防止被垃圾回收
            label.pack(pady=10)
        else:
            tk.Label(top, text="图片加载失败").pack()
    except Exception as e:
        tk.Label(top, text=f"图片显示失败: {e}").pack()

    tk.Label(top, text="If this tool saved your time,").pack()
    tk.Label(top, text="feel free to buy me a coffee.").pack()
    tk.Label(top, text="Your support means a lot to me!").pack()


# --- Main Application Setup ---
root = tk.Tk()
root.title("SFP Register Decoder (SFF-8472)")

# --- Create Menu Bar ---
menubar = tk.Menu(root)
root.config(menu=menubar)



# 获取当前日期，格式为 "Version YYYYMMDD"
today_date = datetime.now().strftime("Version %Y%m%d")

# --- Add Menu with About option ---
about_menu = tk.Menu(menubar, tearoff=0)
menubar.add_cascade(label="About", menu=about_menu)

about_menu.add_command(label=today_date, state="disabled")
about_menu.add_command(label="Developed by Xian.Wu", state="disabled")
about_menu.add_command(label="dakongwuxian@gmail.com", state="disabled")
about_menu.add_command(label="Buy me a coffee ☕", command=show_about_window)

# --- Load explanations from file at startup ---
load_explanations_from_file()

main_frame = tk.Frame(root)
main_frame.pack(padx=10, pady=10, fill='both', expand=True)

# Now, within main_frame, we still use grid for its children
main_frame.grid_rowconfigure(0, weight=1) # Row for the three main sections
main_frame.grid_columnconfigure(0, weight=0) # Column for left_frame (now wider)
main_frame.grid_columnconfigure(1, weight=1) # Column for middle_frame
main_frame.grid_columnconfigure(2, weight=1) # Column for right_frame

left_frame = tk.Frame(main_frame)
left_frame.grid(row=0, column=0, padx=(0, 10), sticky='nsew')
# Configure rows and columns within left_frame for new layout
left_frame.grid_rowconfigure(2, weight=1) # Input A0h section
left_frame.grid_rowconfigure(5, weight=1) # Input A2h section
left_frame.grid_columnconfigure(0, weight=1) # Single column for elements in left_frame

middle_frame = tk.Frame(main_frame)
middle_frame.grid(row=0, column=1, padx=(0, 10), sticky='nsew')
middle_frame.grid_rowconfigure(1, weight=1) # Row for output_text
middle_frame.grid_columnconfigure(0, weight=1) # Single column for elements in middle_frame

# --- A0h Input Section ---
input_label_a0h = tk.Label(left_frame, text="Input A0h 128 or 256bytes data here (byte 128-255 reserved for SFF-8079)")
input_label_a0h.grid(row=0, column=0, sticky='w')

input_a0h_section_frame = tk.Frame(left_frame)
input_a0h_section_frame.grid(row=1, column=0, sticky='nsew')
input_a0h_section_frame.grid_rowconfigure(1, weight=1)
input_a0h_section_frame.grid_columnconfigure(1, weight=1) # Input text column

column_header_a0h = tk.Label(input_a0h_section_frame, text="00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F", font=('Courier New', 10))
column_header_a0h.grid(row=0, column=1, sticky='w') 

line_numbers_a0h = tk.Text(input_a0h_section_frame, width=7, height=16, state='disabled',
                             font=('Courier New', 10), background='lightgrey', relief='flat')
line_numbers_a0h.grid(row=1, column=0, sticky='nswe')

# Note: scrolledtext already has its own scrollbar
input_text = scrolledtext.ScrolledText(input_a0h_section_frame, height=16, width=50, font=('Courier New', 10))
input_text.grid(row=1, column=1, sticky='nswe')
input_text.bind("<ButtonRelease-1>", on_input_click)
input_text.bind("<Button-3>", lambda event: show_context_menu(event, input_text))


# --- A2h Input Section ---
input_label_a2h = tk.Label(left_frame, text="Input A2h 256bytes data here")
input_label_a2h.grid(row=3, column=0, sticky='w', pady=(10,0)) # Padding above

input_a2h_section_frame = tk.Frame(left_frame)
input_a2h_section_frame.grid(row=4, column=0, sticky='nsew')
input_a2h_section_frame.grid_rowconfigure(1, weight=1)
input_a2h_section_frame.grid_columnconfigure(1, weight=1) # Input text column

column_header_a2h = tk.Label(input_a2h_section_frame, text="00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F", font=('Courier New', 10))
column_header_a2h.grid(row=0, column=1, sticky='w') 

line_numbers_a2h = tk.Text(input_a2h_section_frame, width=7, height=16, state='disabled',
                             font=('Courier New', 10), background='lightgrey', relief='flat')
line_numbers_a2h.grid(row=1, column=0, sticky='nswe')

# Note: scrolledtext already has its own scrollbar
input_a2h_text = scrolledtext.ScrolledText(input_a2h_section_frame, height=16, width=50, font=('Courier New', 10))
input_a2h_text.grid(row=1, column=1, sticky='nswe')
input_a2h_text.bind("<ButtonRelease-1>", on_input_click)
input_a2h_text.bind("<Button-3>", lambda event: show_context_menu(event, input_a2h_text))


# Initially populate line numbers
update_line_numbers()
# Bind events to update line numbers when input text changes (e.g., paste or typing)
# These bindings are still valid and useful.
input_text.bind("<KeyRelease>", lambda event: update_line_numbers())
input_text.bind("<<Modified>>", lambda event: root.after_idle(update_line_numbers))
input_text.edit_modified(False) # Reset modified flag after initial setup

input_a2h_text.bind("<KeyRelease>", lambda event: update_line_numbers())
input_a2h_text.bind("<<Modified>>", lambda event: root.after_idle(update_line_numbers))
input_a2h_text.edit_modified(False) # Reset modified flag after initial setup


parse_btn = tk.Button(left_frame, text="Parse Registers", command=parse_registers)
parse_btn.grid(row=5, column=0, pady=5) # Place parse button below A2h section

output_label = tk.Label(middle_frame, text="Decoded Output:")
output_label.grid(row=0, column=0, sticky='w')

output_text = scrolledtext.ScrolledText(middle_frame, height=30, width=50, state='disabled', font=('Courier New', 10))
output_text.grid(row=1, column=0, sticky='nsew')
output_text.bind("<ButtonRelease-1>", on_cursor_click)

right_frame = tk.Frame(main_frame)
right_frame.grid(row=0, column=2, sticky='nsew')
right_frame.grid_rowconfigure(0, weight=0)
right_frame.grid_rowconfigure(1, weight=0)
right_frame.grid_rowconfigure(2, weight=1)
right_frame.grid_columnconfigure(0, weight=1) # Column for label and text
right_frame.grid_columnconfigure(1, weight=0) # Column for the button, minimal width
bit_label_entry_frame = tk.Frame(right_frame)
bit_label_entry_frame.grid(row=0, column=1,sticky='ne')

for i in range(8):
    bit_position = 7 - i # From 7 down to 0
    
    # Label for the bit position
    bit_label = tk.Label(bit_label_entry_frame, text=str(bit_position))
    bit_label.grid(row=0, column=i, padx=1, sticky='e') 

    # Entry for the bit value
    bit_entry = tk.Entry(bit_label_entry_frame, width=1, justify='center', font=('Courier New', 10))
    bit_entry.insert(0, '0') # Default value
    bit_entry.grid(row=1, column=i, padx=1, sticky='e') # sticky='n' to align at top
    bit_entry.bind("<KeyRelease>", update_bit_output_from_entries) # Bind to update function
    bit_entry.bind("<Button-1>", on_bit_entry_click) # Bind click event
    bit_entries.append(bit_entry)

bit_output_label = tk.Label(right_frame, text="Bit Explanation:")
bit_output_label.grid(row=1, column=0, columnspan=1, sticky='nw',pady=5)

# Apply Change Button
apply_change_button = tk.Button(right_frame, text="Apply Change", command=apply_changes)
apply_change_button.grid(row=1, column=1, columnspan=3, sticky='ne',pady=5) # Button next to the label

bit_output_text = scrolledtext.ScrolledText(right_frame, height=30, width=50, state='normal', font=('Courier New', 10))
bit_output_text.grid(row=2, column=0, columnspan=2, sticky='nsew') # columnspan=2 to span label and button columns
bit_output_text.bind("<Button-1>", on_bit_output_click) # Bind single-click event


# Initialize highlight tag style
output_text.tag_config("highlight",  background="yellow", foreground="black")
input_text.tag_config("highlight", background="yellow", foreground="black") 
input_a2h_text.tag_config("highlight", background="yellow", foreground="black") 
bit_output_text.tag_configure("highlight", background="yellow", foreground="black")

#input_text.insert("1.0", "Only HEX numbers are allowed;\nspaces and \\n will be stripped before processing.")

root.mainloop()
