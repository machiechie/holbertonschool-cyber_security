#!/usr/bin/python3
"""
Locates and replaces a string in the heap of a running process.
Usage: ./read_write_heap.py pid search_string replace_string
"""

import sys

def read_write_heap():
    """Main function to perform memory manipulation."""
    if len(sys.argv) != 4:
        sys.exit(1)

    pid = sys.argv[1]
    search_str = sys.argv[2]
    replace_str = sys.argv[3]

    maps_path = "/proc/{}/maps".format(pid)
    mem_path = "/proc/{}/mem".format(pid)

    heap_start = None
    heap_end = None

    try:
        with open(maps_path, 'r') as f:
            for line in f:
                if "[heap]" in line:
                    parts = line.split()
                    addr_range = parts[0].split('-')
                    heap_start = int(addr_range[0], 16)
                    heap_end = int(addr_range[1], 16)
                    break
        
        if not heap_start or not heap_end:
            sys.exit(1)

        with open(mem_path, 'rb+') as f:
            f.seek(heap_start)
            heap_data = f.read(heap_end - heap_start)

            # Find the string in the raw byte data
            try:
                offset = heap_data.index(bytes(search_str, "ascii"))
            except ValueError:
                sys.exit(1)

            # Overwrite the memory
            f.seek(heap_start + offset)
            f.write(bytes(replace_str, "ascii"))
            
            # If the script reaches here successfully:
            print("SUCCESS!", end="") # Matching desired stdout format

    except Exception:
        sys.exit(1)


if __name__ == "__main__":
    read_write_heap()
