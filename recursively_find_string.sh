#!/bin/bash

# Script to recursively find strings in Mach-O executable files
# Usage: ./recursively_find_string.sh [directory] [search_string] [options]

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Default values
DIRECTORY="."
SEARCH_STRING=""
CASE_SENSITIVE=true
VERBOSE=false
OUTPUT_FILE=""
MIN_STRING_LENGTH=4
SHOW_CONTEXT=false
CONTEXT_LINES=2

# Function to display usage
usage() {
    echo "Usage: $0 [OPTIONS] [DIRECTORY] [SEARCH_STRING]"
    echo ""
    echo "Recursively find strings in Mach-O executable files"
    echo ""
    echo "OPTIONS:"
    echo "  -h, --help              Show this help message"
    echo "  -i, --ignore-case       Case insensitive search"
    echo "  -v, --verbose           Verbose output"
    echo "  -o, --output FILE       Save results to file"
    echo "  -l, --min-length N      Minimum string length (default: 4)"
    echo "  -c, --context           Show context around matches"
    echo "  -n, --context-lines N   Number of context lines (default: 2)"
    echo "  --list-only             Only list Mach-O files, don't search"
    echo ""
    echo "EXAMPLES:"
    echo "  $0 /usr/bin password"
    echo "  $0 -i -v . \"secret key\""
    echo "  $0 --output results.txt /Applications NSLog"
    echo "  $0 --list-only /usr/bin"
    exit 1
}

# Function to check if file is Mach-O executable
is_macho_executable() {
    local file="$1"

    # Check if file exists and is readable
    [[ -f "$file" && -r "$file" ]] || return 1

    # Use file command to check if it's a Mach-O executable
    local file_type
    file_type=$(file -b "$file" 2>/dev/null)

    # Check for various Mach-O executable types
    if [[ "$file_type" =~ Mach-O.*executable ]] || \
       [[ "$file_type" =~ Mach-O.*bundle ]] || \
       [[ "$file_type" =~ Mach-O.*dynamically\ linked\ shared\ library ]] || \
       [[ "$file_type" =~ Mach-O.*dynamic\ library ]]; then
        return 0
    fi

    return 1
}

# Function to extract strings from Mach-O file
extract_strings() {
    local file="$1"
    local min_len="$2"

    # Use strings command with minimum length
    strings -a -n "$min_len" "$file" 2>/dev/null || true
}

# Function to search for string in extracted strings
search_in_strings() {
    local strings_output="$1"
    local search_term="$2"
    local case_flag=""

    if [[ "$CASE_SENSITIVE" == false ]]; then
        case_flag="-i"
    fi

    if [[ "$SHOW_CONTEXT" == true ]]; then
        echo "$strings_output" | grep $case_flag -n -C "$CONTEXT_LINES" "$search_term" || true
    else
        echo "$strings_output" | grep $case_flag -n "$search_term" || true
    fi
}

# Function to log message
log() {
    local level="$1"
    shift
    local message="$*"

    case "$level" in
        "INFO")
            echo -e "${BLUE}[INFO]${NC} $message" >&2
            ;;
        "SUCCESS")
            echo -e "${GREEN}[SUCCESS]${NC} $message" >&2
            ;;
        "WARNING")
            echo -e "${YELLOW}[WARNING]${NC} $message" >&2
            ;;
        "ERROR")
            echo -e "${RED}[ERROR]${NC} $message" >&2
            ;;
        "VERBOSE")
            if [[ "$VERBOSE" == true ]]; then
                echo -e "${PURPLE}[VERBOSE]${NC} $message" >&2
            fi
            ;;
    esac
}

# Function to find and process Mach-O files
find_and_process() {
    local search_dir="$1"
    local search_term="$2"
    local list_only="$3"
    local total_files=0
    local processed_files=0
    local files_with_matches=0

    log "INFO" "Searching for Mach-O executables in: $search_dir"

    # Find all files recursively
    while IFS= read -r -d '' file; do
        ((total_files++))

        log "VERBOSE" "Checking file: $file"

        if is_macho_executable "$file"; then
            ((processed_files++))

            if [[ "$list_only" == true ]]; then
                echo -e "${CYAN}$file${NC}"
                continue
            fi

            log "VERBOSE" "Processing Mach-O file: $file"

            # Extract strings
            local strings_output
            strings_output=$(extract_strings "$file" "$MIN_STRING_LENGTH")

            if [[ -n "$search_term" ]]; then
                # Search for the term
                local matches
                matches=$(search_in_strings "$strings_output" "$search_term")

                if [[ -n "$matches" ]]; then
                    ((files_with_matches++))
                    echo -e "\n${GREEN}=== Found matches in: $file ===${NC}"
                    echo "$matches" | while IFS= read -r line; do
                        if [[ "$line" =~ ^[0-9]+: ]]; then
                            # Line with match
                            echo -e "${YELLOW}$line${NC}"
                        else
                            # Context line
                            echo "$line"
                        fi
                    done

                    if [[ -n "$OUTPUT_FILE" ]]; then
                        {
                            echo ""
                            echo "=== Found matches in: $file ==="
                            echo "$matches"
                        } >> "$OUTPUT_FILE"
                    fi
                fi
            else
                # No search term, dump all strings
                echo -e "\n${GREEN}=== Strings from: $file ===${NC}"
                echo "$strings_output" | nl

                if [[ -n "$OUTPUT_FILE" ]]; then
                    {
                        echo ""
                        echo "=== Strings from: $file ==="
                        echo "$strings_output"
                    } >> "$OUTPUT_FILE"
                fi
            fi
        fi
    done < <(find "$search_dir" -type f -print0 2>/dev/null)

    # Summary
    echo -e "\n${BLUE}=== Summary ===${NC}"
    echo "Total files examined: $total_files"
    echo "Mach-O executables found: $processed_files"
    if [[ -n "$search_term" ]]; then
        echo "Files with matches: $files_with_matches"
    fi

    if [[ -n "$OUTPUT_FILE" ]]; then
        log "SUCCESS" "Results saved to: $OUTPUT_FILE"
    fi
}

# Parse command line arguments
LIST_ONLY=false

while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            usage
            ;;
        -i|--ignore-case)
            CASE_SENSITIVE=false
            shift
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -o|--output)
            OUTPUT_FILE="$2"
            shift 2
            ;;
        -l|--min-length)
            MIN_STRING_LENGTH="$2"
            shift 2
            ;;
        -c|--context)
            SHOW_CONTEXT=true
            shift
            ;;
        -n|--context-lines)
            CONTEXT_LINES="$2"
            shift 2
            ;;
        --list-only)
            LIST_ONLY=true
            shift
            ;;
        -*)
            log "ERROR" "Unknown option: $1"
            usage
            ;;
        *)
            if [[ -z "$DIRECTORY" || "$DIRECTORY" == "." ]]; then
                DIRECTORY="$1"
            elif [[ -z "$SEARCH_STRING" ]]; then
                SEARCH_STRING="$1"
            else
                log "ERROR" "Too many arguments"
                usage
            fi
            shift
            ;;
    esac
done

# Validate directory
if [[ ! -d "$DIRECTORY" ]]; then
    log "ERROR" "Directory does not exist: $DIRECTORY"
    exit 1
fi

# Check for required tools
for tool in file strings find grep; do
    if ! command -v "$tool" &> /dev/null; then
        log "ERROR" "Required tool not found: $tool"
        exit 1
    fi
done

# Initialize output file if specified
if [[ -n "$OUTPUT_FILE" ]]; then
    > "$OUTPUT_FILE"
    log "INFO" "Output will be saved to: $OUTPUT_FILE"
fi

# Main execution
if [[ "$LIST_ONLY" == true ]]; then
    log "INFO" "Listing Mach-O executable files only"
    find_and_process "$DIRECTORY" "" true
elif [[ -z "$SEARCH_STRING" ]]; then
    log "WARNING" "No search string provided. Will dump all strings from all Mach-O files."
    read -p "Continue? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log "INFO" "Operation cancelled"
        exit 0
    fi
    find_and_process "$DIRECTORY" "" false
else
    log "INFO" "Searching for string: '$SEARCH_STRING'"
    find_and_process "$DIRECTORY" "$SEARCH_STRING" false
fi
