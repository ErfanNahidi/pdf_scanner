import subprocess
from pathlib import Path

def pretty_output(PDFiD_result, head=False):
    data_lines = PDFiD_result.stdout.splitlines()
    if not head:
        data_lines = data_lines[:2]

    # Pretty subprocess (pdfid) output
    keyword_counts = {}
    for line in data_lines:
        # Strip whitespace
        line = line.strip()
        if not line:
            continue
        # Split by whitespace, maxsplit=1 to separate key and value
        parts = line.split(maxsplit=1)
        if len(parts) == 2:
            key, value = parts
            try:
                keyword_counts[key] = int(value)
            except ValueError:
                # Not a number, ignore or handle differently
                pass

    return keyword_counts

def PDFiD_subprocess(file_path_arg, pretty=True):
    file_path = Path.home() / file_path_arg

    result = subprocess.run(
        ["python3", "pdfid", file_path], capture_output=True, text=True
    )

    if pretty:
        result = pretty_output(result)

    return result


# Level 1
def level_1(dict):
    """
    takes a pretty output and returns PDFiD result (none-xml)
    """
    suspicious_keys = ["/JS", "/JavaScript", "/AA", "/OpenAction"]
    threats_found = {}
    threats = 0

    print("Hunting Basic Level 1 Threats...\n")
    for key in suspicious_keys:
        count = dict.get(key, 0)
        if count > 0:
            threats_found[key] = count
            threats += 1
        print(f"{key}: {count}")
    print("\n")

    if threats_found:
        print("Suspicous Items Found:\n")
