#!/usr/bin/env python3
import argparse, time, json, os, hashlib, itertools, multiprocessing
from datetime import datetime
from rich.console import Console
from rich.table import Table
from tqdm import tqdm

console = Console()

# --- Utilities ---
def hash_word(word, algo):
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
    expected_lengths = {
        "md5": 32, "sha1": 40, "sha256": 64, "sha512": 128,
        "sha3_256": 64, "sha3_512": 128, "blake2b": 128, "blake2s": 64
    }
    return len(hash_value) == expected_lengths.get(algo, 0) and all(c in "0123456789abcdef" for c in hash_value.lower())

def detect_algo(hash_value):
    length_map = {
        32: "md5", 40: "sha1", 64: ["sha256", "sha3_256", "blake2s"],
        128: ["sha512", "sha3_512", "blake2b"]
    }
    candidates = length_map.get(len(hash_value), [])
    return candidates[0] if isinstance(candidates, list) else candidates

# --- Dictionary Mode ---
def run_dictionary(target_hash, algo, wordlist_path, verbose):
    attempts = 0
    found = None
    with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
        words = f.read().splitlines()
    for word in tqdm(words, desc="Dictionary", unit="word"):
        attempts += 1
        if verbose: print(f"Trying: {word}")
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
    return variants

def run_rule(target_hash, algo, wordlist_path, rulefile, verbose):
    attempts = 0
    found = None
    rules = ["append123", "reverse", "capitalize", "replace"]
    if rulefile:
        with open(rulefile, "r") as f:
            rules = [line.strip() for line in f if line.strip()]
    with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
        words = f.read().splitlines()
    for word in tqdm(words, desc="Rule-based", unit="word"):
        for variant in mutate(word, rules):
            attempts += 1
            if verbose: print(f"Trying: {variant}")
            if hash_word(variant, algo) == target_hash:
                found = variant
                break
        if found: break
    return found, attempts

# --- Brute Mode ---
def run_brute(target_hash, algo, charset, maxlen):
    manager = multiprocessing.Manager()
    counter = manager.Value("i", 0)
    lock = manager.Lock()

    def worker(word):
        with lock:
            counter.value += 1
        return word if hash_word(word, algo) == target_hash else None

    candidates = (''.join(p) for l in range(1, maxlen+1) for p in itertools.product(charset, repeat=l))
    with multiprocessing.Pool() as pool, tqdm(total=sum(len(charset)**l for l in range(1, maxlen+1)), desc="Brute-force", unit="word") as pbar:
        for result in pool.imap_unordered(worker, candidates, chunksize=1000):
            pbar.update(counter.value - pbar.n)
            if result:
                return result
    return None

# --- Mask Mode ---
def parse_mask(mask):
    mask_map = {
        "?l": "abcdefghijklmnopqrstuvwxyz",
        "?u": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "?d": "0123456789",
        "?s": "!@#$%^&*"
    }
    charset_list = []
    i = 0
    while i < len(mask):
        if mask[i:i+2] in mask_map:
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
        if verbose: print(f"Trying: {word}")
        if hash_word(word, algo) == target_hash:
            found = word
            break
    return found, attempts

# --- Combo Mode ---
def run_combo(target_hash, algo, wordlist1, wordlist2, verbose):
    attempts = 0
    found = None
    with open(wordlist1, "r", encoding="utf-8", errors="ignore") as f1, open(wordlist2, "r", encoding="utf-8", errors="ignore") as f2:
        list1 = f1.read().splitlines()
        list2 = f2.read().splitlines()
    for w1 in tqdm(list1, desc="Combinator", unit="word"):
        for w2 in list2:
            for combo in [w1 + w2, w2 + w1]:
                attempts += 1
                if verbose: print(f"Trying: {combo}")
                if hash_word(combo, algo) == target_hash:
                    found = combo
                    break
            if found: break
        if found: break
    return found, attempts

# --- Logging & GUI ---
def log_json(result, stats):
    os.makedirs("logs", exist_ok=True)
    with open("logs/cracked.json", "a", encoding="utf-8") as f:
        json.dump({"result": result, "stats": stats}, f)
        f.write("\n")

def show_status(mode, algo, hash_value, attempts, found):
    table = Table(title="Cracking Status")
    table.add_column("Mode")
    table.add_column("Algorithm")
    table.add_column("Hash")
    table.add_column("Attempts")
    table.add_column("Found")
    table.add_row(mode, algo.upper(), hash_value, str(attempts), found or "N/A")
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

    hashes = []
    if args.hash:
        hashes.append(args.hash)
    elif args.hashfile:
        with open(args.hashfile, "r") as f:
            hashes = [line.strip() for line in f if line.strip()]
    else:
        console