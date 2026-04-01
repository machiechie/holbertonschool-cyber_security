#!/usr/bin/python3
"""
Locates and replaces a string in the heap of a running process.
Usage: ./read_write_heap.py pid search_string replace_string
"""

import sys
import os


def print_error_and_exit(msg):
    """Prints error message to stdout and exits with status 1."""
    print(msg)
    sys.exit(1)


def read_write_heap():
    """Main function to perform memory manipulation."""
    if len(sys.argv) != 4:
        print_error_and_exit("Usage: read_write_heap.py pid search replace")

    pid = sys.argv[1]
    search_str = sys.argv[2]
    replace_str = sys.argv[3]

    if not pid.isdigit():
        print_error_and_exit("PID must be a number")

    # 1. Find the heap range in /proc/[pid]/maps
    maps_path = "/proc/{}/maps".format(pid)
    mem_path = "/proc/{}/mem".format(pid)

    heap_start = None
    heap_end = None

    try:
        with open(maps_path, 'r') as f:
            for line in f:
                if "[heap]" in line:
                    # Line format: 'start-end permissions offset dev inode pathname'
                    parts = line.split()
                    addr_range = parts[0].split('-')
                    heap_start = int(addr_range[0], 16)
                    heap_end = int(addr_range[1], 16)
                    break
    except Exception as e:
        print_error_and_exit("Can't open maps file: {}".format(e))

    if not heap_start or not heap_end:
        print_error_and_exit("Could not find [heap] in maps.")

    # 2. Search and overwrite in /proc/[pid]/mem
    try:
        with open(mem_path, 'rb+') as f:
            f.seek(heap_start)
            heap_data = f.read(heap_end - heap_start)

            # Find the string in the raw byte data
            try:
                offset = heap_data.index(bytes(search_str, "ascii"))
            except ValueError:
                print_error_and_exit("String '{}' not found in heap.".format(search_str))

            # Seek to the absolute position and write
            f.seek(heap_start + offset)
            f.write(bytes(replace_str + '\0', "ascii")) # Null-terminate for C safety
            print("[*] Found and replaced string at offset {:x}".format(offset))

    except Exception as e:
        print_error_and_exit("Can't access memory: {}".format(e))


if __name__ == "__main__":
    read_write_heap()
