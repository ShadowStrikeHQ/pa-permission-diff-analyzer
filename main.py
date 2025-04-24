#!/usr/bin/env python3

import argparse
import difflib
import logging
import os
import stat
import sys
from pathlib import Path
from typing import List, Dict, Tuple

try:
    from rich.console import Console
    from rich.table import Column, Table
    from rich.theme import Theme

    RICH_INSTALLED = True
except ImportError:
    RICH_INSTALLED = False
    print(
        "Rich library not found. Install with: pip install rich"
        "Rich formatting will be disabled."
    )


# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)


def setup_argparse() -> argparse.ArgumentParser:
    """
    Sets up the argument parser for the pa-permission-diff-analyzer tool.

    Returns:
        argparse.ArgumentParser: The configured argument parser.
    """
    parser = argparse.ArgumentParser(
        description=(
            "Compares file system permissions between two directories or"
            "snapshots, highlighting discrepancies."
        )
    )

    parser.add_argument(
        "dir1",
        type=str,
        help="Path to the first directory or snapshot.",
        metavar="DIR1",
    )
    parser.add_argument(
        "dir2",
        type=str,
        help="Path to the second directory or snapshot.",
        metavar="DIR2",
    )

    parser.add_argument(
        "--recursive",
        action="store_true",
        help="Recursively compare subdirectories.",
    )

    parser.add_argument(
        "--ignore-ownership",
        action="store_true",
        help="Ignore differences in file ownership (user/group).",
    )

    parser.add_argument(
        "--report-file",
        type=str,
        help="Path to save the report to a file.",
        metavar="REPORT_FILE",
    )
    parser.add_argument(
        "--output-format",
        type=str,
        choices=["text", "rich"],
        default="text",
        help="Format of the output: text or rich (requires rich library). Defaults to 'text'.",
    )

    parser.add_argument(
        "--log-level",
        type=str,
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        default="INFO",
        help="Set the logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL). Defaults to INFO.",
    )

    return parser


def get_file_permissions(
    path: Path, ignore_ownership: bool = False
) -> Dict[str, str]:
    """
    Retrieves file permissions for a given file path.

    Args:
        path (Path): The path to the file.
        ignore_ownership (bool): Flag to ignore owner details if True.

    Returns:
        Dict[str, str]: A dictionary containing file permissions, mode, owner, group.
        Returns an empty dictionary if the file does not exist or is inaccessible.
    """
    try:
        stat_info = os.stat(path)
        mode = stat.filemode(stat_info.st_mode)
        owner = stat_info.st_uid
        group = stat_info.st_gid

        if not ignore_ownership:
            try:
                import pwd, grp

                owner = pwd.getpwuid(stat_info.st_uid).pw_name
                group = grp.getgrgid(stat_info.st_gid).gr_name
            except ImportError:
                logging.warning(
                    "pwd and grp modules not available (possibly on Windows)."
                    "Using UID/GID instead of user/group names."
                )
            except KeyError:
                logging.warning(
                    "User or group ID not found. Using UID/GID instead of"
                    " user/group names."
                )
    except FileNotFoundError:
        logging.error(f"File not found: {path}")
        return {}  # File does not exist.
    except PermissionError:
        logging.error(f"Permission denied: {path}")
        return {}  # Insufficient permissions.
    except Exception as e:
        logging.error(f"Error accessing {path}: {e}")
        return {}  # Handle other potential errors.

    return {
        "mode": mode,
        "owner": str(owner),
        "group": str(group),
    }


def compare_directories(
    dir1: Path,
    dir2: Path,
    recursive: bool = False,
    ignore_ownership: bool = False,
) -> List[Tuple[str, Dict[str, str], Dict[str, str]]]:
    """
    Compares file permissions between two directories.

    Args:
        dir1 (Path): The path to the first directory.
        dir2 (Path): The path to the second directory.
        recursive (bool): Whether to recursively compare subdirectories.
        ignore_ownership (bool): Whether to ignore differences in file ownership.

    Returns:
        List[Tuple[str, Dict[str, str], Dict[str, str]]]: A list of tuples,
        where each tuple contains the filename, permissions from dir1, and
        permissions from dir2.
        Returns an empty list if either directory does not exist.
    """
    if not dir1.is_dir():
        logging.error(f"Directory not found: {dir1}")
        return []
    if not dir2.is_dir():
        logging.error(f"Directory not found: {dir2}")
        return []

    diffs: List[Tuple[str, Dict[str, str], Dict[str, str]]] = []

    files1 = {
        str(f.relative_to(dir1)): f for f in dir1.rglob("*") if f.is_file()
    }  # Use rglob for recursive listing
    files2 = {
        str(f.relative_to(dir2)): f for f in dir2.rglob("*") if f.is_file()
    }  # Use rglob for recursive listing

    all_files = set(files1.keys()).union(files2.keys())

    for filename in all_files:
        path1 = dir1 / filename
        path2 = dir2 / filename

        perms1 = get_file_permissions(path1, ignore_ownership)
        perms2 = get_file_permissions(path2, ignore_ownership)

        if perms1 != perms2:
            diffs.append((filename, perms1, perms2))

        if recursive:
            if path1.is_dir() and path2.is_dir():
                diffs.extend(
                    compare_directories(path1, path2, recursive, ignore_ownership)
                )

    return diffs


def generate_text_report(
    diffs: List[Tuple[str, Dict[str, str], Dict[str, str]]],
    dir1: str,
    dir2: str,
) -> str:
    """
    Generates a text report from the permission differences.

    Args:
        diffs (List[Tuple[str, Dict[str, str], Dict[str, str]]]): A list of permission differences.
        dir1 (str): The path to the first directory.
        dir2 (str): The path to the second directory.

    Returns:
        str: The text report as a string.
    """
    report = "Permission Difference Report\n"
    report += f"Comparing: {dir1} vs {dir2}\n\n"

    if not diffs:
        report += "No permission differences found.\n"
        return report

    for filename, perms1, perms2 in diffs:
        report += f"File: {filename}\n"
        report += f"  {dir1}: {perms1}\n"
        report += f"  {dir2}: {perms2}\n"
        report += "\n"

    return report


def generate_rich_report(
    diffs: List[Tuple[str, Dict[str, str], Dict[str, str]]],
    dir1: str,
    dir2: str,
) -> str:
    """
    Generates a Rich-formatted report.
    Requires the `rich` library.

    Args:
        diffs (List[Tuple[str, Dict[str, str], Dict[str, str]]]): A list of permission differences.
        dir1 (str): The path to the first directory.
        dir2 (str): The path to the second directory.

    Returns:
        str: A string representing the Rich-formatted output.
    """

    if not RICH_INSTALLED:
        print(
            "Rich library not installed.  Falling back to text format. "
            "Install rich with `pip install rich` to enable rich reporting."
        )
        return generate_text_report(diffs, dir1, dir2)

    custom_theme = Theme(
        {
            "report_title": "bold magenta",
            "section_title": "bold cyan",
            "file_path": "italic yellow",
            "dir1": "green",
            "dir2": "red",
            "no_diffs": "green",
        }
    )

    console = Console(theme=custom_theme)

    table = Table(
        title="[report_title]Permission Difference Report[/report_title]",
        show_header=True,
        header_style="bold blue",
    )
    table.add_column("[section_title]File[/section_title]", style="file_path")
    table.add_column(f"[section_title]{dir1}[/section_title]", style="dir1")
    table.add_column(f"[section_title]{dir2}[/section_title]", style="dir2")

    if not diffs:
        console.print("[no_diffs]No permission differences found.[/no_diffs]")
        return ""

    for filename, perms1, perms2 in diffs:
        table.add_row(
            filename,
            str(perms1),
            str(perms2),
        )

    console.print(table)
    return ""


def main() -> None:
    """
    Main function to execute the pa-permission-diff-analyzer tool.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    logging.getLogger().setLevel(args.log_level)

    dir1 = Path(args.dir1).resolve()
    dir2 = Path(args.dir2).resolve()

    if not dir1.exists():
        logging.error(f"Directory not found: {dir1}")
        sys.exit(1)
    if not dir2.exists():
        logging.error(f"Directory not found: {dir2}")
        sys.exit(1)

    try:
        diffs = compare_directories(
            dir1, dir2, args.recursive, args.ignore_ownership
        )

        if args.output_format == "rich":
            report = generate_rich_report(diffs, args.dir1, args.dir2)
        else:
            report = generate_text_report(diffs, args.dir1, args.dir2)

        if args.report_file:
            try:
                with open(args.report_file, "w") as f:
                    f.write(report)
                logging.info(f"Report saved to: {args.report_file}")
            except IOError as e:
                logging.error(f"Error writing to file: {e}")
                sys.exit(1)
        else:
            print(report)  # Output to stdout if no report file specified

    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()