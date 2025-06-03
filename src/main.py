import argparse
import sys
from pathlib import Path
from xml.dom.minidom import parse, parseString

from pdfid.pdfid import PDFiD
from utils.filter_xml import filter_xml_keywords


class CustomArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        print(f"Error: {message}")
        self.print_help()
        sys.exit(2)


parser = CustomArgumentParser(
    description="Scans PDFs for any malicious activity to triage and \
                                 analyze them",
    usage="%(prog)s [options] source_file",
)

#  positional arguments
parser.add_argument(
    "-l",
    "--level",
    type=int,
    help="security severity level, minimum of 1 and maximum of 3. The higher the stricter the program will be, defaults to 2",
    default=1,
    choices=[1, 2, 3],
)

parser.add_argument(
    "-d", "--directory", type=str, help="Path to the PDF directory you want to diagnose"
)

parser.add_argument(
    "-f", "--file", type=str, help="Path to the PDF file you want to diagnose"
)

parser.add_argument(
    "-w",
    "--watch",
    type=str,
    help="Path to the PDF directory you want to watch to scan and secure PDFs",
)

parser.add_argument(
    "-v", "--verbose", action="store_true", help="provide operation information"
)

# Parsed arguments
args = parser.parse_args()

directory_path_arg = ""
if args.directory:
    directory_path_arg = str(Path.home() / args.directory)

file_path_arg = ""
if args.file:
    file_path_arg = str(Path.home() / args.file)

level_arg = args.level
watch_arg = args.watch


if (
    (file_path_arg and directory_path_arg)
    or (watch_arg and file_path_arg)
    or (watch_arg and directory_path_arg)
):
    parser.error(
        "incompatible options: file & directory or watch can't be used at the same time"
    )
elif not file_path_arg and not directory_path_arg:
    parser.error("atmost one of the options -f or -d must be defined")

result = None
if level_arg == 1:
    keyword_counts = PDFiD(file_path_arg)
    xml_obj = keyword_counts
    result = filter_xml_keywords(xml_obj)

print(result)
