#!/usr/bin/env python3
import argparse
import hashlib
import itertools
import json
import os
from datetime import datetime
from rich.console import Console
from rich.table import Table
from tqdm import tqdm

console = Console()

# --- Utilities ---
def hash_word(word, algo):
    """Return hash of the word using specified algorithm."""
    word = word.strip().encode()
    if algo == "md5":
        return hashlib.md5(word).hexdigest()
    elif algo == "sha1":
        return hashlib.sha1(word).hexdigest()
    elif algo == "sha256":
        return hashlib.sha256(word).hexdigest()
    elif algo == "sha512":
        return hashlib.sha512(word).hexdigest()
    elif algo == "sha3_256":
        return hashlib.sha3_256(word).hexdigest()
    elif algo == "sha3_512":
        return hashlib.sha3_512(word).hexdigest()
    elif algo == "blake2b":
        return hashlib.blake2b(word).hexdigest()
    elif algo == "blake2s":
        return hashlib.blake2s(word).hexdigest()
    return None

def validate_hash(hash_value, algo):
    """Check if hash length matches expected algorithm length and contains valid hex chars."""
    expected_lengths = {
        "md5": 32, "sha1": 40, "sha256": 64, "sha512": 128,
        "sha3_256": 64, "sha3_512": 128, "blake2b": 128, "blake2s": 64
    }
    if algo is None:
        return False
    return len(hash_value) == expected_lengths.get(algo, 0) and all(c in "0123456789abcdef" for c in hash_value.lower())

def detect_algo(hash_value):
    """Detect possible hash algorithm based on length."""
    length_map = {
        32: "md5",
        40: "sha1",
        64: ["sha256", "sha3_256", "blake2s"],
        128: ["sha512", "sha3_512", "blake2b"]
    }
    candidates = length_map.get(len(hash_value), [])
    if isinstance(candidates, list):
        return candidates[0] if candidates else None
    return candidates

# --- Dictionary Mode ---
def run_dictionary(target_hash, algo, wordlist_path, verbose):
    attempts = 0
    found = None
    with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
        for raw in tqdm(f, desc="Dictionary", unit="word"):
            word = raw.strip()
            attempts += 1
            if verbose:
                console.print(f"[blue]Trying:[/blue] {word}")
            if hash_word(word, algo) == target_hash:
                found = word
                break
    return found, attempts

# --- Rule Mode ---
def mutate(word, rules):
    variants = [word]
    for rule in rules:
        if rule == "append123":
            variants.append(word + "123")
        elif rule == "reverse":
            variants.append(word[::-1])
        elif rule == "capitalize":
            variants.append(word.capitalize())
        elif rule == "replace":
            variants.append(word.replace("a", "@").replace("s", "$").replace("o", "0"))
    # remove duplicates while preserving order
    seen = set()
    out = []
    for v in variants:
        if v not in seen:
            seen.add(v)
            out.append(v)
    return out

def run_rule(target_hash, algo, wordlist_path, rulefile, verbose):
    attempts = 0
    found = None
    rules = ["append123", "reverse", "capitalize", "replace"]
    if rulefile and os.path.exists(rulefile):
        with open(rulefile, "r", encoding="utf-8", errors="ignore") as f:
            file_rules = [line.strip() for line in f if line.strip()]
            if file_rules:
                rules = file_rules
    with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
        for raw in tqdm(f, desc="Rule-based", unit="word"):
            word = raw.strip()
            for variant in mutate(word, rules):
                attempts += 1
                if verbose:
                    console.print(f"[blue]Trying:[/blue] {variant}")
                if hash_word(variant, algo) == target_hash:
                    found = variant
                    break
            if found:
                break
    return found, attempts

# --- Brute-force Mode ---
def run_brute(target_hash, algo, charset, maxlen, verbose):
    if not charset:
        charset = "abcdefghijklmnopqrstuvwxyz0123456789"
    if not maxlen or maxlen < 1:
        maxlen = 4
    attempts = 0
    total = sum(len(charset) ** l for l in range(1, maxlen + 1))
    gen = (''.join(p) for l in range(1, maxlen + 1) for p in itertools.product(charset, repeat=l))
    found = None
    for word in tqdm(gen, total=total, desc="Brute-force", unit="word"):
        attempts += 1
        if verbose:
            console.print(f"[blue]Trying:[/blue] {word}")
        if hash_word(word, algo) == target_hash:
            found = word
            break
    return found, attempts

# --- Mask Mode ---
def parse_mask(mask):
    mask_map = {"?l": "abcdefghijklmnopqrstuvwxyz",
                "?u": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
                "?d": "0123456789",
                "?s": "!@#$%^&*"}
    charset_list = []
    i = 0
    while i < len(mask):
        if i + 1 < len(mask) and mask[i:i+2] in mask_map:
            charset_list.append(mask_map[mask[i:i+2]])
            i += 2
        else:
            charset_list.append(mask[i])
            i += 1
    return (''.join(candidate) for candidate in itertools.product(*charset_list))

def run_mask(target_hash, algo, mask, verbose):
    attempts = 0
    found = None
    for word in tqdm(parse_mask(mask), desc="Mask", unit="word"):
        attempts += 1
        if verbose:
            console.print(f"[blue]Trying:[/blue] {word}")
        if hash_word(word, algo) == target_hash:
            found = word
            break
    return found, attempts

# --- Combo Mode ---
def run_combo(target_hash, algo, wordlist1, wordlist2, verbose):
    attempts = 0
    found = None
    with open(wordlist1, "r", encoding="utf-8", errors="ignore") as f1, open(wordlist2, "r", encoding="utf-8", errors="ignore") as f2:
        list1 = [w.strip() for w in f1 if w.strip()]
        list2 = [w.strip() for w in f2 if w.strip()]
    for w1 in tqdm(list1, desc="Combinator", unit="word"):
        for w2 in list2:
            for combo in (w1 + w2, w2 + w1):
                attempts += 1
                if verbose:
                    console.print(f"[blue]Trying:[/blue] {combo}")
                if hash_word(combo, algo) == target_hash:
                    found = combo
                    break
            if found:
                break
        if found:
            break
    return found, attempts

# --- Logging ---
def log_json(result, stats):
    os.makedirs("logs", exist_ok=True)
    entry = {"result": result, "stats": stats, "logged_at": datetime.utcnow().isoformat() + "Z"}
    with open("logs/cracked.json", "a", encoding="utf-8") as f:
        json.dump(entry, f)
        f.write("\n")

def show_status(mode, algo, hash_value, attempts, found):
    table = Table(title="Cracking Status")
    table.add_column("Mode")
    table.add_column("Algorithm")
    table.add_column("Hash")
    table.add_column("Attempts")
    table.add_column("Found")
    table.add_row(mode, (algo or "N/A").upper(), hash_value, str(attempts), found or "N/A")
    console.clear()
    console.print(table)

# --- Main ---
def main():
    parser = argparse.ArgumentParser(description="HashCracker Pro")
    parser.add_argument("--mode", required=True, choices=["dictionary", "rule", "brute", "mask", "combo"])
    parser.add_argument("--hash", help="Single hash to crack")
    parser.add_argument("--hashfile", help="File containing hashes")
    parser.add_argument("--algo", choices=["md5", "sha1", "sha256", "sha512", "sha3_256", "sha3_512", "blake2b", "blake2s"])
    parser.add_argument("--wordlist", help="Path to wordlist")
    parser.add_argument("--wordlist2", help="Second wordlist for combo")
    parser.add_argument("--charset", help="Charset for brute-force")
    parser.add_argument("--maxlen", type=int, help="Max length for brute-force")
    parser.add_argument("--mask", help="Mask pattern")
    parser.add_argument("--rules", help="Path to rule file")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--force", action="store_true", help="Force cracking even if hash format is invalid")
    args = parser.parse_args()

    # Load hashes
    hashes = []
    if args.hash:
        hashes.append(args.hash.strip())
    elif args.hashfile and os.path.exists(args.hashfile):
        with open(args.hashfile, "r", encoding="utf-8", errors="ignore") as f:
            hashes = [line.strip() for line in f if line.strip()]
    else:
        console.print("[red]Error: Provide --hash or --hashfile[/red]")
        return

    # Process each hash
    for hash_value in hashes:
        algo = args.algo or detect_algo(hash_value)
        if algo is None:
            console.print("[red]Cannot detect algorithm. Use --algo[/red]")
            if not args.force:
                continue
        if not args.force and not validate_hash(hash_value, algo):
            console.print(f"[red]Invalid hash format for algorithm {algo}[/red]")
            continue

        found = None
        attempts = 0

        if args.mode == "dictionary":
            if not args.wordlist:
                console.print("[red]--wordlist required[/red]")
                continue
            found, attempts = run_dictionary(hash_value, algo, args.wordlist, args.verbose)
        elif args.mode == "rule":
            if not args.wordlist:
                console.print("[red]--wordlist required[/red]")
                continue
            found, attempts = run_rule(hash_value, algo, args.wordlist, args.rules, args.verbose)
        elif args.mode == "brute":
            if not args.charset or not args.maxlen:
                console.print("[red]--charset and --maxlen required[/red]")
                continue
            found, attempts = run_brute(hash_value, algo, args.charset, args.maxlen, args.verbose)
        elif args.mode == "mask":
            if not args.mask:
                console.print("[red]--mask required[/red]")
                continue
            found, attempts = run_mask(hash_value, algo, args.mask, args.verbose)
        elif args.mode == "combo":
            if not args.wordlist or not args.wordlist2:
                console.print("[red]--wordlist and --wordlist2 required[/red]")
                continue
            found, attempts = run_combo(hash_value, algo, args.wordlist, args.wordlist2, args.verbose)

        show_status(args.mode, algo, hash_value, attempts, found)

        # Log result
        stats = {"mode": args.mode, "algo": algo, "hash": hash_value, "attempts": attempts, "found": found, "timestamp": datetime.now().isoformat()}
        log_json(found, stats)

    console.print("[green]Run complete. Check logs/cracked.json[/green]")

if __name__ == "__main__":
    main()
