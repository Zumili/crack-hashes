# crack-hashes
A CPU-based tool to crack salted and unsalted hashes like MD5, SHA1, SHA256 and more in python > 3.6.  
It is quite fast for unsalted hash-lists! For salted hash-lists not very much...  
If there is just one salted hash in an unsalted hash-list, it uses a much slower cracking methode!!  

This tool is for legal use only! (◔/‿\◔)  
Don't use this tool for illegal activities!  (⋗_⋖)

```bash
  Name            : crack-hashes.py
  Created By      : Zumili
  Documentation   : https://github.com/Zumili/crack-hashes
  License         : The MIT License
  Version         : 1.0.0
```

## How to install?

`git clone https://github.com/Zumili/crack-hashes`

## How to run?

`python crack-hashes.py -h`

```bash
 Options Short/Long  | Type | Description
 ====================+======+==========================================
       hash|hashfile | Str  | hash, hash:salt pair or file
       dict|mask     | Str  | dictionay or mask or even charset
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
```


First use internal help for some information.  
`python crack-hashes.py -h`

Show hash types  
`python crack-hashes.py -m ?`

Show attack mode information  
`python crack-hashes.py -a ?`

Show charsets and masks  
`python crack-hashes.py -c ?`

Show worker information  
`python crack-hashes.py -w ?`

Show output file information  
`python crack-hashes.py -o ?`

### Examples

Here you can find some examples

#### Mask Attack

Cracking one single MD5 [-m md5] hash without any salt using lowercase charset [-c 0] in incremental mask mode [-a 1].  
`python crack-hashes.py -m md5 -a 1 -c 0 b5c0b187fe309af0f4d35982fd961d7e`  

Same as above but with salt. Be careful if you have symbols like ">" in the salt, include it into ""  
`python crack-hashes.py -m md5 -a 1 -c 0 "a4e1bb78474e9a67e527a7264a797de1:@->-->--"`  

You can also use a hash-file [hashes-md5.txt] and set a mask [-c ?l?l?l?l], also use incremental mode [-i 1] to start at 1 character.  
`python crack-hashes.py -m md5 -a 1 -i 1 -c ?l?l?l?l hashes-md5.txt`  

Same as above but with sha256 and a salted hash-file. If it is mask attack mode you can place the mask instead of the wordlist. We also use no output [-n] option to suppress additional information except the found hashes.  
`python crack-hashes.py -m sha256 -a 1 -i 1 -n hashes-sha256-salt.txt ?l?l?l?l`  

If the salt is added as a postfix use [-p]  
`python crack-hashes.py -m sha512 -a 1 -i 1 -p -n hashes-sha512-salt-post.txt ?l?l?l?l`  

If you remember some parts of the plain you can include it into the mask  
`python crack-hashes.py -m md5 -a 1 -c sn?l?l?l?lrs ce922d89a6c244fb0c5aff66bc46e9be`  

#### Dictionary / Wordlist Attack

Cracking one single sha1 with a wordlist.  
`python crack-hashes.py -m sha1 -a 0 ebe53c61982711f13af8bbc09844e4e2849268ba wordlist-1K.txt`  

Or crack a list of salted sha1 hashes with a wordlist with no output [-n] except the found hashes  
`python crack-hashes.py -m sha1 -a 0 -n hashes-sha1-salt.txt wordlist-1K.txt`  

#### Excluding characters

It is possible to exclude a string of characters from all specified charsets [-x]  
`python crack-hashes.py -m md5 -a 1 -c 0 -x "bcdefghijklmoquvxyz" 5badcaf789d3d1d09794d8f021f40f0e`  

#### Using multiple workers

To speed things up a bit, you can use multiple workers e.g. [-w 3]  
`python crack-hashes.py -m sha1 -a 1 -w 3 -c s?u?l?lgat?l?d 5b8de134e4ab93717f48fd101487a5319236941e`  

#### Redirect to a file

Instead of using the [-o <file>] parameter to store the found hashes and candidates in a file, it is also possible to redirect the output to a file.  
`python crack-hashes.py -m sha1 -a 1 -c 0 -x "bdfghijlmnoquv" -n 0803df4ff1650933d2ffe6be04d4b21432134252 > potfile.txt`

#### Running in background

You can also run the script in background with using e.g. `nohup` at the beginning of line and `>& /dev/null &` at the end to prevent any output file from being created.  
`nohup python crack-hashes.py -m md5 -a 1 -c 0 -x "bcdfghijlmnopquv" -o potfile.txt -n 29f491121c63af2a883378c50e1f8d9f >& /dev/null &`

To stop the processes created with nohub use:  
`jobs`  
*>> [1] + Running nohup python crack-hashes.py ... options ...*  
`kill %1`  

## Version
1.0

## License
[The MIT License](https://opensource.org/licenses/MIT)

## Who?
Written by Zumili ([thomas-messmer.com](http://thomas-messmer.com)) for scientific purposes only.
