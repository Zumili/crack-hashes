#!usr/bin/python3
# This tool is for legal use only!
# Don't use this tool for illegal activities!

import os
import time
import itertools
import string
import hashlib
import sys
import signal
import argparse
import random
import threading
import multiprocessing
from multiprocessing import Process
import re

__version__ = '1.0.0'

info = """
  Name            : crack-hashes.py
  Created By      : Zumili
  Documentation   : https://github.com/Zumili/crack-hashes
  License         : The MIT License
  Version         : %s
""" % (__version__)


# Used to break loops in main processes and its animation thread
done = False
# Create jobs array for workers
jobs = []


# AttackConfig holding all necessary elements for the attack processes
class AttackConfig(object):

    id = 0
    hash_salt_pair_list = []
    wordlist = ""
    hashlib_type_str = ""
    charset_list = []
    output_file = ""
    use_postfix = False
    no_info = False
    increment = 0

    # The class "constructor" - It's actually an initializer
    def __init__(self, id, hash_salt_pair_list, wordlist,
                 hashlib_type_str, charset_list,
                 output_file, use_postfix,
                 no_info, increment):
        self.id = id
        self.hash_salt_pair_list = hash_salt_pair_list
        self.wordlist = wordlist
        self.hashlib_type_str = hashlib_type_str
        self.charset_list = charset_list
        self.output_file = output_file
        self.use_postfix = use_postfix
        self.no_info = no_info
        self.increment = increment


def signal_handler(signal, frame):

    global done
    done = True

    for i in range(len(jobs)):
        jobs[i].terminate()

    sys.exit(0)


def animate(mpa_hash_per_sec, mpa_done, mpv_hashes_found_list,
            hashes_count, mpa_line_count, wl_length):

    for c in itertools.cycle(['|', '/', '-', '\\']):
        if done or all(mpa_done):
            break

        hash_per_sec_str = "KH/s: "
        wl_perc_str = ""
        for i in range(len(mpa_hash_per_sec)):
            khps = mpa_hash_per_sec[i]/1000
            hash_per_sec_str = (hash_per_sec_str +
                                "{:.0f}".format(khps) + " | ")
            if mpa_line_count[0] != 0:
                perc_done = mpa_line_count[i]*100/wl_length
                wl_perc_str = (wl_perc_str +
                               "{:.1f}".format(perc_done) + "% ")

        hashes_percent = "{:.1f}".format(len(mpv_hashes_found_list) *
                                         100/hashes_count)

        sys.stdout.write('\r' + c + " F:" +
                         str(len(mpv_hashes_found_list)) + "/" +
                         str(hashes_count) + " " +
                         hashes_percent + "% " +
                         hash_per_sec_str +
                         wl_perc_str)
        sys.stdout.flush()
        time.sleep(1.2)


# This function is more or less crap...
def calc_count_val(lst):
    magic = 200000
    salts_count = 0
    for i in lst:
        if i[1] != "":
            salts_count += 1
    if salts_count == 0:
        salts_count = 1
    salts_percent = int(salts_count * 100 / len(lst))
    if salts_percent == 0:
        salts_percent = 1
    diff_for_length = int(len(lst)/500)
    if diff_for_length == 0:
        diff_for_length = 1
    if salts_count == 1:
        count_val = int(magic/(salts_count*diff_for_length))
    else:
        count_val = int(magic/(salts_count/8))

    return count_val


def attack_wordlist(attack_config,
                    mpa_hash_per_sec,
                    mpl_found_pair,
                    mpa_done,
                    mpa_line_count,
                    lock):

    done = False
    hash_per_sec = 0
    worker_passes = 0
    tmp_passes = 0
    skipped = 0

    # Create local variables for performance increase!
    # Do not use attack_config.<element> in loops!
    id = attack_config.id
    hash_salt_pair_list = attack_config.hash_salt_pair_list
    wordlist = attack_config.wordlist
    use_postfix = attack_config.use_postfix
    hashlib_type_str = attack_config.hashlib_type_str
    no_info = attack_config.no_info
    output_file = attack_config.output_file

    start_time = time.time()

    count_val = calc_count_val(hash_salt_pair_list)

    f = open(wordlist, 'r', encoding="ISO-8859-1")

    try:
        line = f.readline()
    except:
        pass

    # Create a set from the list of lists, by first creating a tuple
    hash_salt_pair_tup = [tuple(t) for t in hash_salt_pair_list]
    hash_salt_pair_set = set(hash_salt_pair_tup)

    set_size_changed = False
    set_el_to_discard = set()

    while line:

        # remove "\n" from line
        line_stripped = line.strip()
        # line_stripped = line.replace('\n', '')
        # line_stripped = line[:-1]

        tmp_passes += 1
        if tmp_passes > count_val:
            tmp_passes = 0
            worker_passes += (count_val+1)

            elapsed_time_fl = (time.time() - start_time)
            start_time = time.time()
            hash_per_sec = int(len(hash_salt_pair_set) *
                               count_val/elapsed_time_fl)

            lock.acquire()
            mpa_hash_per_sec[id] = hash_per_sec
            mpa_line_count[id] = worker_passes
            lock.release()

            if set_size_changed:
                for elem in set_el_to_discard:
                    hash_salt_pair_set.discard(elem)
                set_size_changed = False

            if done:
                break_loop = True
                break

        rehash = True
        last_salt = None

        for hash_set_element in hash_salt_pair_set:

            if rehash or last_salt is not hash_set_element[1]:

                if not use_postfix:
                    wordlist_line = (hash_set_element[1])+line_stripped
                else:
                    wordlist_line = line_stripped+hash_set_element[1]

                act_hash_hex = hashlib.new(hashlib_type_str,
                                           wordlist_line
                                           .encode()).hexdigest()
                rehash = False
                last_salt = hash_set_element[1]

            if(hash_set_element[0] == act_hash_hex):

                lock.acquire()
                mpl_found_pair.append(hash_set_element)
                write_potfile(output_file,
                              hash_set_element,
                              line_stripped)
                lock.release()

                print_found_info(id, act_hash_hex,
                                 (hash_set_element[1] + ":" +
                                  line_stripped),
                                 worker_passes+tmp_passes,
                                 no_info)

                set_el_to_discard.add(hash_set_element)
                set_size_changed = True

                if(len(hash_salt_pair_set) == 0):
                    done = True
                    lock.acquire()
                    mpa_done[id] = True
                    lock.release()
                    break

        # use realine() to read next line
        try:
            line = f.readline()
        except:
            skipped += 1

    f.close()
    if not no_info:
        print("\nLines skipped: %i" % skipped)


def attack_mask(attack_config,
                mpa_hash_per_sec,
                mpl_found_pair,
                mpa_done,
                mpa_line_count,
                lock):

    done = False
    hash_per_sec = 0
    worker_passes = 0
    tmp_passes = 0
    brute_force_string = ""
    max_mask_length = 20
    mask_start = 1
    last_found_list_length = 0

    # Create local variables for performance increase!
    # Do not use attack_config.<element> in loops!
    id = attack_config.id
    hash_salt_pair_list = attack_config.hash_salt_pair_list
    charset_list = attack_config.charset_list
    use_postfix = attack_config.use_postfix
    hashlib_type_str = attack_config.hashlib_type_str
    no_info = attack_config.no_info
    increment = attack_config.increment
    output_file = attack_config.output_file

    start_time = time.time()

    count_val = calc_count_val(hash_salt_pair_list)

    # Mask Attack
    if increment == 0:
        max_mask_length = len(charset_list)
        mask_start = max_mask_length
    # Mask Attack increment
    if increment >= 1:
        max_mask_length = 20
        mask_start = increment

    # Create a set from the list of lists, by first creating tuples
    hash_salt_pair_tup = [tuple(t) for t in hash_salt_pair_list]
    hash_salt_pair_set = set(hash_salt_pair_tup)

    for n in range(mask_start, max_mask_length+1):

        if done:
            break

        if not no_info:
            print("\n[!] P%s at character %i" % (id, n))

        charset_tmp = charset_list.copy()

        # For incremental, remove list elements until 1, 2, ... remaining
        for i in range(n, len(charset_list)):
            charset_tmp.pop(0)

        for xs in itertools.product(*charset_tmp, repeat=1):

            if done:
                break

            saved = ''.join(xs)

            tmp_passes += 1

            if tmp_passes > count_val:
                tmp_passes = 0
                worker_passes += (count_val+1)

                elapsed_time_fl = (time.time() - start_time)
                start_time = time.time()
                hash_per_sec = int(len(hash_salt_pair_set) *
                                   count_val/elapsed_time_fl)

                lock.acquire()  # ########################################
                mpa_hash_per_sec[id] = hash_per_sec
                # If fixed mask we can describe it as a long wordlist
                if increment == 0:
                    mpa_line_count[id] = worker_passes

                # Following code looks for hash:salt pairs in found list
                # and removes them in the working set
                # but only if new hashes has been added to found list
                if(len(mpl_found_pair) > last_found_list_length):
                    temp = []
                    while hash_salt_pair_set:
                        found = False
                        x = hash_salt_pair_set.pop()

                        for j in range(last_found_list_length,
                                       len(mpl_found_pair)):
                            if x == mpl_found_pair[j]:
                                found = True
                                break

                        if not found:
                            temp.append(x)

                    while temp:
                        hash_salt_pair_set.add(temp.pop())

                    # if not no_info:
                        # print("\nSet Length of P%i is: %i"
                              # % (id, len(hash_salt_pair_set)))

                    last_found_list_length = len(mpl_found_pair)

                if(len(hash_salt_pair_set) == 0):
                    mpa_done[id] = True
                    done = True
                lock.release()  # ########################################

                if done:
                    break

            rehash = True
            act_hash_hex = ""
            last_salt = ""

            for hash_set_element in hash_salt_pair_set:

                if rehash or last_salt is not hash_set_element[1]:

                    if not use_postfix:
                        brute_force_string = hash_set_element[1]+saved
                        # bfs = "%s%s" % (hse[1],saved) is slower!
                    else:
                        brute_force_string = saved+hash_set_element[1]

                    act_hash_hex = hashlib.new(hashlib_type_str,
                                               brute_force_string
                                               .encode()).hexdigest()
                    rehash = False
                    last_salt = hash_set_element[1]

                if(hash_set_element[0] == act_hash_hex):

                    lock.acquire()
                    # Add hash to global found list
                    mpl_found_pair.append(hash_set_element)
                    write_potfile(output_file,
                                  hash_set_element,
                                  saved)
                    lock.release()

                    print_found_info(id, act_hash_hex,
                                     (hash_set_element[1] + ":" +
                                      saved),
                                     worker_passes+tmp_passes,
                                     no_info)


def write_potfile(file, lst, candidate):
    # if file != '':
    if file is None or file == '':
        return
        file = "crack-hashes.potfile"
    f = open(file, "a")

    # Check if a salt is in the list
    if lst[1] == "":
        output_str = lst[0]+":"+candidate+"\n"
    else:
        output_str = lst[0]+":"+lst[1]+":"+candidate+"\n"

    f.write(output_str)

    f.close()

    return


def exclude_chars_from_string(string, exclude):
    tmp_str = string.translate({ord(i): None for i in exclude})
    return tmp_str


def shuffle_string(string):
    l = list(string)
    random.shuffle(l)
    tmp_str = ''.join(l)
    return tmp_str


def split_string(string, index, amount):

    part_length = int(len(string) / amount + 0.5)
    parts = [string[i:i+part_length] for i in range(0,
                                                    len(string),
                                                    part_length)]

    # if one element to much in list
    if(len(parts) == amount+1):
        # append last element to second last
        parts[len(parts)-2] = parts[len(parts)-2] + parts[len(parts)-1]
        # remove last element
        parts.pop()

    return parts[index]


def split_list(lst, index, amount):

    part_length = int(len(lst) / amount + 0.5)
    parts = [lst[i:i+part_length] for i in range(0,
                                                 len(lst),
                                                 part_length)]

    # if one element to much in list
    if(len(parts) == amount+1):
        # append last element to second last
        parts[len(parts)-2] = parts[len(parts)-2] + parts[len(parts)-1]
        # remove last element
        parts.pop()

    return parts[index]


def modify_append_charset(charset,
                          charset_array,
                          exclude_chars,
                          shuffle_chars):
    tmp_str = charset
    if exclude_chars != "":
        tmp_str = exclude_chars_from_string(tmp_str, exclude_chars)
    if shuffle_chars:
        charset_array.append(shuffle_string(tmp_str))
    else:
        charset_array.append(tmp_str)


def build_charset_from_mask(worker_index,
                            workers,
                            char_selector,
                            exclude_chars,
                            shuffle_chars,
                            mask_length):
    charset_array = []
    index = 0

    if char_selector == "0":
        char_selector = "?l" * mask_length  # abcdefghijklmnopqrstuvwxyz
    elif char_selector == "1":
        char_selector = "?u" * mask_length  # ABCDEFGHIJKLMNOPQRSTUVWXYZ
    elif char_selector == "2":
        char_selector = "?d" * mask_length  # 0123456789
    elif char_selector == "3":
        char_selector = "?h" * mask_length  # 0123456789abcdef
    elif char_selector == "4":
        char_selector = "?H" * mask_length  # 0123456789ABCDEF
    elif char_selector == "5":
        char_selector = "?s" * mask_length  # space!"#$%&'()*+,-./:;<=
    elif char_selector == "6":              # >?@[\]^_`{|}~
        char_selector = "?a" * mask_length  # ?l?u?d?s
    elif char_selector == "7":
        char_selector = "?b" * mask_length  # 0x00 - 0xff
    elif char_selector == "8":
        char_selector = "?y" * mask_length  #
    elif char_selector == "9":
        char_selector = "?z" * mask_length  #

    while index < len(char_selector):

        if(char_selector[index] == "?" and index+1 < len(char_selector)):
            if char_selector[index+1] == "?":
                index += 1
            elif char_selector[index+1] == "l":
                tmp_charset = string.ascii_lowercase
                modify_append_charset(tmp_charset, charset_array,
                                      exclude_chars, shuffle_chars)
                index += 2
            elif char_selector[index+1] == "u":
                tmp_charset = string.ascii_uppercase
                modify_append_charset(tmp_charset, charset_array,
                                      exclude_chars, shuffle_chars)
                index += 2
            elif char_selector[index+1] == "d":
                tmp_charset = string.digits
                modify_append_charset(tmp_charset, charset_array,
                                      exclude_chars, shuffle_chars)
                index += 2
            elif char_selector[index+1] == "h":
                tmp_charset = exclude_chars_from_string(string.hexdigits,
                                                        "ABCDEF")
                modify_append_charset(tmp_charset, charset_array,
                                      exclude_chars, shuffle_chars)
                index += 2
            elif char_selector[index+1] == "H":
                tmp_charset = exclude_chars_from_string(string.hexdigits,
                                                        "abcdef")
                modify_append_charset(tmp_charset, charset_array,
                                      exclude_chars, shuffle_chars)
                index += 2
            elif char_selector[index+1] == "s":
                tmp_charset = string.punctuation + " "
                modify_append_charset(tmp_charset, charset_array,
                                      exclude_chars, shuffle_chars)
                index += 2
            elif char_selector[index+1] == "a":
                tmp_charset = (string.ascii_lowercase +
                               string.ascii_uppercase +
                               string.punctuation + " ")
                modify_append_charset(tmp_charset, charset_array,
                                      exclude_chars, shuffle_chars)
                index += 2
            elif char_selector[index+1] == "b":
                tmp_charset = (string.ascii_lowercase +
                               string.ascii_uppercase + string.digits)
                modify_append_charset(tmp_charset, charset_array,
                                      exclude_chars, shuffle_chars)
                index += 2
            elif char_selector[index+1] == "y":
                tmp_charset = (string.ascii_lowercase +
                               string.ascii_uppercase + string.digits)
                modify_append_charset(tmp_charset, charset_array,
                                      exclude_chars, shuffle_chars)
                index += 2
            elif char_selector[index+1] == "z":
                tmp_charset = (string.ascii_lowercase +
                               string.ascii_uppercase + string.digits)
                modify_append_charset(tmp_charset, charset_array,
                                      exclude_chars, shuffle_chars)
                index += 2

        elif(char_selector[index] != "?" and index+1 <= len(char_selector)):
            charset_array.append(char_selector[index])
            index += 1
        else:
            index += 1

    # reverse search for the first charset which has more
    # than worker amount of chars in it
    for i in range(0, len(charset_array)):
        idx_arr = len(charset_array)-1-i
        # if found split it into more or less equal parts
        if(len(charset_array[idx_arr]) >= workers):
            charset_array[idx_arr] = split_string(charset_array[idx_arr],
                                                  worker_index,
                                                  workers)
            break
    return charset_array


def print_found_info(id, hash, candidate, worker_passes, no_info):

    if no_info is False:
        print('\n\n[|] Hash found in P%i' % id)
        print("[|] Time: ", time.strftime('%H:%M:%S'))
        print("[|] Keywords attempted: ", worker_passes, '\n')
        print(hash+':'+candidate+'\n')
    else:
        print(hash+':'+candidate)
    return


def print_help(msg):
    print_options(msg)


def print_usage():
    print("""Usage: python %s [options]... hash|hashfile [dict|mask]\n"""
          % sys.argv[0])
    print("Try -h, --help for more help.")


def print_options(msg):
    print(msg)
    print("""Usage: python %s [options]... hash|hashfile [dict|mask]\n

 Options Short/Long  | Type | Description
 ====================+======+==========================================
       hash|hashfile | Str  | hash, hash:salt pair or file
       dict|mask     | Str  | dictionary or mask or even charset
 -m, --hash-type     | Num  | [-m ?] hash mode e.g. md5, sha256
 -a, --attack        | Num  | [-a ?] [-a 0] wordlist [-a 1] Mask Attack
 -c, --charset-mask  | Num  | [-c ?] charset [0-9] or mask [?l?l?l?l?d?d]
 -x, --exclude-chars | Str  | string of characters removed from charset
 -w, --worker        | Num  | [-w ?] worker count, minimum 1 worker
 -p, --post-fix      |      | selects if salt is postfix
 -s, --shuffle       |      | shuffle selected charsets
 -i, --increment     |      | enable mask increment mode and set position
 -n, --no-info       |      | print only found hash:[salt:]candidate pair
 -e, --exampes       |      | print some examples
 -o, --output-file   | Str  | output file to store found hashes
 """ % sys.argv[0])
    return


def print_worker_count_info():
    print("""Worker Count - option [-w <worker>]

  [-w 0], [-w 1] or [not used] always use 1 worker
  Maximum worker count depends on maximum CPU count,
  attack mode and amount of hashes in file
  Max CPU Count: %i recommended %i
  """ % (int(multiprocessing.cpu_count()),
         int(multiprocessing.cpu_count())-1))
    return


def print_output_file_info():
    print("""Output File - option [-o <out-file>]

  Must contain at least 3 characters!
    """)
    return


def print_hash_modes():
    tmp_list = list(hashlib.algorithms_available)
    tmp_list.sort()  # sorts normally by alphabetical order
    tmp_list.sort(key=len)  # sorts by length
    tmp_str = '\n   '.join(tmp_list)
    print("Hash Modes - option [-m <mode>]")
    print("\nAvailable hashing algortihms:\n")
    print("  ", tmp_str)

    return


def break_long_string(long_string, break_index, space):
    if len(long_string) <= break_index:
        return long_string
    tmp_space = " "*space
    tmp_string = (long_string[:break_index] +
                  '\n' +
                  tmp_space +
                  long_string[break_index:])
    return tmp_string


def print_charsets():
    print("""Character Sets - option [-c <selector>]

    # | *  | Charset
======+=================================
    0 | ?l | %s
    1 | ?u | %s
    2 | ?d | %s
    3 | ?h | %s
    4 | ?H | %s
    5 | ?s | %s
    6 | ?a | %s
    7 | -- | %s
    8 | ?y | %s
    9 | ?z | %s

    Use [-c 1] to set all elements of mask to upper-case letters.

    Use [-c ?l?l?l?d?d?d] to set first 3 to lower-case letters,
    last 3 to digits

    Use [-c Pass?l?l?l?l456] if you know it begins with "Pass" and
    ends with "456" and has 4 lower-case letters in between
    """ % (string.ascii_lowercase,
           string.ascii_uppercase,
           string.digits,
           exclude_chars_from_string(string.hexdigits, "ABCDEF"),
           exclude_chars_from_string(string.hexdigits, "abcdef"),
           string.punctuation + " ",
           break_long_string(string.ascii_lowercase +
                             string.ascii_uppercase +
                             string.punctuation + " ",
                             57,
                             13),
           "-",
           break_long_string(string.ascii_lowercase +
                             string.ascii_uppercase +
                             string.punctuation + " ",
                             57,
                             13),
           break_long_string(string.ascii_lowercase +
                             string.ascii_uppercase +
                             string.punctuation + " ",
                             57,
                             13)))
    return


def print_attack_mode_info():
    print("""Attack Mode - option [-a <mode>]

    # | Mode
======+=================================
    0 | Wordlist
      | - Needs a given wordlist
      | --------------------------------
    1 | Mask Attack (fix length or incremental)
      | - Needs a given mask or charset option [-c]
    """)
    return


def print_increment_info():
    print("""Increment Mode - option [-i <mode>]

    Use [-i] or [-i 1] to set start position to 1 character
    Use e.g. [-i 6] to set start position to 6 characters
    Range: [0-19]
    """)
    return


def print_examples():
    print(""" Examples - option [-e]

    # | Command / Description
======+=================================
    1 | Mask Attack with first character known as "Z" then 4 unknown
      | lower case charsets and last known character "i"
      | python crack-hashes.py -m md5 -a 1 -c Z?l?l?l?li
      | 3a9c9e14a64eb0253ea385d2298e54fd
      | --------------------------------
    2 | Same as above, but as a hash:salt pair
      | python crack-hashes.py -m md5 -a 1 -c Z?l?l?l?li
      | 61afe1abb75692845d606232b823fa83:3a9c9e14
      | --------------------------------
    3 | Same as above, but using [-p] to use salt internally as post-fix
      | python crack-hashes.py -m md5 -a 1 -c Z?l?l?l?li -p
      | e66fa45ae05908c8bf6a207f4c43a726:3a9c9e14
      | --------------------------------
    3 | Wordlist Attack on a list of hashes using 3 workers
      | python crack-hashes.py -m md5 -a 0 -w 3 hashes.txt wordlist.txt
      | --------------------------------
      | More examples on https://github.com/Zumili/crack-hashes
""")


def get_file_length(file, mode=0):

    count = 0
    if mode == 0:
        thefile = open(file, 'rb')
        while 1:
            buffer = thefile.read(8192*1024)
            if not buffer:
                break
            count += buffer.count(b'\n')
        thefile.close()

    return count


def main(argv):

    # Version check
    assert sys.version_info >= (3, 0)

    # created variables
    hash_salt_pair_list = []
    charset_list = ""
    hashlib_type_str = "md5"
    total_passes = 0
    worker_count = 1
    wordlist_length = 0

    if not len(argv) > 0:
        print_usage()
        sys.exit()

    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('-h', '--help', action='store_true')
    parser.add_argument('hash', nargs='?',
                        default="")
    parser.add_argument('wordlist', nargs='?',
                        default="")
    parser.add_argument('-m', '--mode')
    parser.add_argument('-c', '--charset-mask')
    parser.add_argument('-x', '--exclude-chars',
                        default="")
    parser.add_argument('-w', '--worker')
    parser.add_argument('-a', '--attack')
    parser.add_argument('-p', '--post-fix', action='store_true',
                        default=False)
    parser.add_argument('-s', '--shuffle-chars', action='store_true',
                        default=False)
    parser.add_argument('-i', '--increment',
                        default=0)
    parser.add_argument('-n', '--no-info', action='store_true')
    parser.add_argument('-e', '--examples', action='store_true')
    parser.add_argument('-o', '--output-file')

    args = parser.parse_args()

    if args.help is True:
        print_help("")
        sys.exit()
    if args.examples is True:
        print_examples()
        sys.exit()

    hash_mode = args.mode
    charset_mask = args.charset_mask
    exclude_chars = args.exclude_chars
    worker_count = args.worker
    attack_mode = args.attack
    use_postfix = args.post_fix
    shuffle_chars = args.shuffle_chars
    increment = args.increment
    output_file = args.output_file
    no_info = args.no_info

    # Test increment parameter
    if increment is None:  # None means option is used but not set!
        increment = 1
    try:
        increment = int(increment)
        if increment not in range(0, 20):
            sys.exit()
    except:
        print_increment_info()
        sys.exit()

    # Test for extended option help
    if hash_mode == "?":
        print_hash_modes()
        sys.exit()
    if attack_mode == "?":
        print_attack_mode_info()
        sys.exit()
    if(charset_mask == "?"):
        print_charsets()
        sys.exit()
    if worker_count == "?":
        print_worker_count_info()
        sys.exit()
    if output_file == "?":
        print_output_file_info()
        sys.exit()

    # Test hash_mode parameter
    if hash_mode in hashlib.algorithms_available:
        hashlib_type_str = hash_mode
    else:
        print_hash_modes()
        sys.exit()

    # Test attack_mode parameter
    try:
        attack_mode = int(attack_mode)
        if attack_mode not in range(0, 2):
            sys.exit()
    except:
        print_attack_mode_info()
        sys.exit()

    # Test wordlist - attack mode combination
    if(args.wordlist == "" and attack_mode == 0):
        print_help("\nWordlist mode but no wordlist selected!")
        sys.exit()
    elif(args.wordlist != "" and attack_mode == 0):
        if os.path.isfile(args.wordlist):
            if not no_info:
                print("Checking wordlist...")
            wordlist_length = get_file_length(args.wordlist)
            if not no_info:
                print("Wordlist file: %s" % args.wordlist)
                print("Wordlist Length:", wordlist_length)
        else:
            print ("\nWordlist: %s not exist" % args.wordlist)
            print_help("")
            sys.exit()
    # Overwrite charset_mask with args.wordlist if mask attack
    # hashcat style, we don't need [-c] option anymore
    elif(args.wordlist != "" and attack_mode == 1):
        charset_mask = args.wordlist

    if(charset_mask is None and attack_mode == 1):
        print_help("\nMask mode but no mask or charset [-c] given!")
        sys.exit()

    try:
        if int(charset_mask) in range(0, 10) and increment == 0:
            increment = 1
    except:
        pass

    if args.hash == "":
        print_help("\nNo hash or hashfile given!")
        sys.exit()

    # Test if hash is a hash-file or a single hash
    # If it is a file read max. 10000 lines of hashes and salts
    # into hash_salt_pair_list
    if os.path.isfile(args.hash):
        if not no_info:
            print("Hash file: %s" % args.hash)
        f = open(args.hash)
        line = f.readline()
        counter = 0
        while line:
            hash_salt_pair = line.strip().split(":")

            if len(hash_salt_pair) == 2:
                hash_salt_pair_list.append(hash_salt_pair)
            elif len(hash_salt_pair) == 1:
                hash_salt_pair.append("")
                hash_salt_pair_list.append(hash_salt_pair)
            counter += 1
            if(counter > 10000):
                print("Not more than 10000 hashes at one time!")
                break
            line = f.readline()
        f.close()

    # If it is a single hash or hash:salt pair, only add this to the list
    else:
        hash_salt_pair = args.hash.split(":")

        regex = re.compile("^[a-fA-F0-9]+$")
        if not bool(regex.match(hash_salt_pair[0])):
            print("Wrong hash given!")
            sys.exit()

        if len(hash_salt_pair) == 2:
            hash_salt_pair_list.append(hash_salt_pair)
        elif len(hash_salt_pair) == 1:
            hash_salt_pair.append("")
            hash_salt_pair_list.append(hash_salt_pair)

    if(len(hash_salt_pair_list) == 0):
        print("No hashes in list. Something went wrong!")
        sys.exit()

    # Test output_file parameter
    if output_file is None:
        output_file = ""
    elif output_file != "" and len(output_file) < 3:
        print_output_file_info()
        sys.exit()

    cpu_count = multiprocessing.cpu_count()

    # Test worker_count parameter
    if worker_count is not None:
        try:
            worker_count = int(worker_count)
            if worker_count not in range(1, cpu_count+1):
                sys.exit()
        except:
            print_worker_count_info()
            sys.exit()
    else:
        worker_count = 1

    # Print a warning if all CPU cores are used
    if worker_count == cpu_count and not no_info:
        print("""\n WARNING !!!
 Using all cores will slow down everything else on your computer.
        """)
        a = input("Start anyway? Use y/Y for YES n/N for NO! ")
        if not (a == 'y' or a == 'Y' or a == 'yes' or
                a == 'Yes' or a == 'z' or a == 'Z'):
            sys.exit()

    signal.signal(signal.SIGINT, signal_handler)

    if attack_mode == 0 and len(hash_salt_pair_list) < worker_count:
        worker_count = len(hash_salt_pair_list)

    # Create "lock", "manager" and "managed elements" for multiprocessing
    lock = multiprocessing.Lock()
    manager = multiprocessing.Manager()
    mpa_hash_per_sec = manager.Array('i', range(worker_count))
    mpl_found_pair = manager.list()
    mpa_done = manager.Array('i', [0] * int(worker_count))
    mpa_line_count = manager.Array('i', [0] * int(worker_count))

    if no_info is False:
        print(info)
        print("[+] Start Time: ", time.strftime('%H:%M:%S'))
        if args.hash != "":
            print('[|] Hash:', args.hash)
        if output_file != "":
            print('[|] Output-File:', output_file)

    # Start selected amount of workers and append them to jobs array
    for i in range(0, (worker_count)):

        # Only build a charset_list if attack mode is mask attack
        if attack_mode == 1:
            charset_list = build_charset_from_mask(i,
                                                   worker_count,
                                                   charset_mask,
                                                   exclude_chars,
                                                   shuffle_chars,
                                                   20)
            # Test if final charset_list has been created successfully
            if len(charset_list) == 0:
                print_charsets()
                sys.exit()
            hash_salt_pair_part = hash_salt_pair_list
            if increment == 0:
                wordlist_length = 1
                for j in range(0, len(charset_list)):
                    wordlist_length *= len(charset_list[j])

        # Split the hash-list into more or less equal parts for each
        # worker if possible, for wordlist mode
        if attack_mode == 0:
            if(len(hash_salt_pair_list) >= worker_count):
                hash_salt_pair_part = split_list(hash_salt_pair_list,
                                                 i,
                                                 worker_count)
            else:
                hash_salt_pair_part = hash_salt_pair_list

        if no_info is False:
            print("[|] Charsets: Worker %i\n" % i, charset_list)

        attack_config = AttackConfig(i, hash_salt_pair_part,
                                     args.wordlist, hashlib_type_str,
                                     charset_list, output_file,
                                     use_postfix, no_info,
                                     increment)
        if attack_mode == 0:
            p = Process(target=attack_wordlist, args=(attack_config,
                                                      mpa_hash_per_sec,
                                                      mpl_found_pair,
                                                      mpa_done,
                                                      mpa_line_count,
                                                      lock))
        else:
            p = Process(target=attack_mask, args=(attack_config,
                                                  mpa_hash_per_sec,
                                                  mpl_found_pair,
                                                  mpa_done,
                                                  mpa_line_count,
                                                  lock))

        jobs.append(p)
        p.start()
        if no_info is False:
            print("Starting worker", (i))

    time.sleep(2.5)

    # If info is not suppressed, start new thread
    # to show H/s for each worker
    if no_info is False:

        t = threading.Thread(target=animate,
                             args=(mpa_hash_per_sec,
                                   mpa_done,
                                   mpl_found_pair,
                                   len(hash_salt_pair_list),
                                   mpa_line_count,
                                   wordlist_length))
        t.start()

    # Join all processes to wait for their termination
    for i in range(0, (worker_count)):
        jobs[i].join()

    global done
    done = True
    if no_info is False:
        print("\n[+] Stop Time: ", time.strftime('%H:%M:%S'))
        print("\nFound: " + str(len(mpl_found_pair)) + " / " +
              str(len(hash_salt_pair_list)))

if __name__ == "__main__":
    multiprocessing.freeze_support()
    main(sys.argv[1:])
