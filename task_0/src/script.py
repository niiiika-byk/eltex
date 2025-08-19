import sys

def count_characters(file_path):
    
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            content = file.read()
            char_count = len(content)
            is_even = char_count % 2 == 0
            return char_count, is_even
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "main":
    if len(sys.argv) != 2:
        print("Usage: python file_analyzer.py <file_path>")
        sys.exit(1)
    
    file_path = sys.argv[1]
    count, is_even = count_characters(file_path)
    print(f"File: {file_path}")
    print(f"Character count: {count}")
    print(f"Count is even: {'Yes' if is_even else 'No'}")