# remove_columns_and_equals.py
import os

def process_file(input_path, output_path):
    with open(input_path, 'r', encoding='utf-8', errors='ignore') as infile, \
         open(output_path, 'w', encoding='utf-8') as outfile:

        for line in infile:
            # Skip empty lines safely
            if not line.strip():
                outfile.write(line)
                continue

            # Split by whitespace to remove first two columns
            parts = line.split()
            if len(parts) > 2:
                # Join the rest of the columns back into a string
                new_line = ' '.join(parts[2:])
            else:
                # Not enough columns to remove, just keep as is
                new_line = line.strip()

            # Remove everything after '=' (if present)
            if '=' in new_line:
                new_line = new_line.split('=')[0].strip()

            outfile.write(new_line + '\n')

def main():
    input_files = ['chrome.trace', 'firefox.trace']
    for fname in input_files:
        if os.path.exists(fname):
            outname = f"cleaned_{fname}"
            process_file(fname, outname)
            print(f"Processed: {fname} -> {outname}")
        else:
            print(f"File not found: {fname}")

if __name__ == "__main__":
    main()
